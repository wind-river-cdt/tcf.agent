/*******************************************************************************
 * Copyright (c) 2008, 2012 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * This module implements DWARF expressions evaluation.
 */

#include <tcf/config.h>

#if ENABLE_ELF && ENABLE_DebugContext

#include <assert.h>
#include <stdio.h>
#include <tcf/framework/events.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/trace.h>
#include <tcf/services/dwarf.h>
#include <tcf/services/dwarfio.h>
#include <tcf/services/dwarfexpr.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/elf-loader.h>
#include <tcf/services/vm.h>

U8_T dwarf_expression_obj_addr = 0;
U8_T dwarf_expression_pm_value = 0;

static int sStackFrame = 0;
static LocationExpressionState * sState = NULL;
static ELF_Section * sSection = NULL;
static U8_T sSectionOffs = 0;
static PropertyValue * sValue = NULL;

static LocationPiece * add_piece(void) {
    LocationPiece * Piece = NULL;
    if (sState->pieces_cnt >= sState->pieces_max) {
        sState->pieces_max += 4;
        sState->pieces = (LocationPiece *)tmp_realloc(sState->pieces, sState->pieces_max * sizeof(LocationPiece));
    }
    Piece = sState->pieces + sState->pieces_cnt++;
    memset(Piece, 0, sizeof(LocationPiece));
    return Piece;
}

static StackFrame * get_stack_frame(PropertyValue * sValue) {
    StackFrame * Info = NULL;
    if (sValue->mFrame == STACK_NO_FRAME) return NULL;
    if (get_frame_info(sValue->mContext, sValue->mFrame, &Info) < 0) exception(errno);
    return Info;
}

ObjectInfo * get_parent_function(ObjectInfo * Info) {
    while (Info != NULL) {
        switch (Info->mTag) {
        case TAG_global_subroutine:
        case TAG_inlined_subroutine:
        case TAG_subroutine:
        case TAG_subprogram:
        case TAG_entry_point:
            return Info;
        }
        Info = Info->mParent;
    }
    return NULL;
}

static U8_T read_address(void) {
    U8_T addr = 0;
    ELF_Section * section = NULL;
    CompUnit * Unit = sValue->mObject->mCompUnit;

    addr = dio_ReadAddress(&section);
    addr = elf_map_to_run_time_address(sState->ctx, Unit->mFile, section, (ContextAddress)addr);
    if (errno) str_exception(errno, "Cannot get object run-time address");
    return addr;
}

static U8_T get_fbreg(void) {
    PropertyValue FP;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    ObjectInfo * Parent = get_parent_function(sValue->mObject);
    U8_T addr = 0;

    if (Parent == NULL) str_exception(ERR_INV_DWARF, "OP_fbreg: no parent function");
    memset(&FP, 0, sizeof(FP));
    read_and_evaluate_dwarf_object_property(sState->ctx, sStackFrame, Parent, AT_frame_base, &FP);
    assert(get_stack_frame(&FP) == sState->stack_frame);

    if (FP.mPieceCnt == 1 && FP.mPieces[0].reg != NULL && FP.mPieces[0].bit_size == 0) {
        if (read_reg_value(sState->stack_frame, FP.mPieces[0].reg, &addr) < 0) exception(errno);
    }
    else {
        addr = get_numeric_property_value(&FP);
    }
    dio_EnterSection(&Unit->mDesc, sSection, sSectionOffs + sState->code_pos);
    return addr + dio_ReadS8LEB128();
}

static U8_T evaluate_tls_address(U8_T Offset) {
    U8_T addr = 0;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    U8_T DioPos = dio_GetPos();

    if (!context_has_state(sState->ctx)) str_exception(ERR_INV_CONTEXT,
        "Thread local variable, but context is not a thread");

    addr = get_tls_address(sState->ctx, Unit->mFile) + Offset;

    dio_EnterSection(&Unit->mDesc, sSection, DioPos);
    return addr;
}

static void evaluate_implicit_pointer(uint8_t op) {
    Trap trap;
    PropertyValue PV;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    int ArgSize = op == OP_GNU_implicit_pointer && Unit->mDesc.mVersion < 3 ? Unit->mDesc.mAddressSize : (Unit->mDesc.m64bit ? 8 : 4);
    ContextAddress id = dio_ReadUX(ArgSize);
    U4_T Offset = dio_ReadULEB128();
    U8_T DioPos = dio_GetPos();
    ObjectInfo * Info = find_object(get_dwarf_cache(Unit->mFile), id);
    if (Info == NULL) str_exception(ERR_INV_DWARF, "OP_implicit_pointer: invalid object reference");
    memset(&PV, 0, sizeof(PV));
    if (set_trap(&trap)) {
        read_and_evaluate_dwarf_object_property(sState->ctx, sStackFrame, Info, AT_location, &PV);
        clear_trap(&trap);
    }
    else if (trap.error == ERR_SYM_NOT_FOUND) {
        read_and_evaluate_dwarf_object_property(sState->ctx, sStackFrame, Info, AT_const_value, &PV);
    }
    else {
        exception(trap.error);
    }
    assert(sValue->mBigEndian == PV.mBigEndian);
    if (PV.mPieces != NULL) {
        U4_T Cnt = 0;
        U4_T BitOffset = 0;
        while (Cnt < PV.mPieceCnt) {
            LocationPiece * OrgPiece = PV.mPieces + Cnt++;
            if (OrgPiece->bit_size == 0) OrgPiece->bit_size = OrgPiece->size * 8;
            if (BitOffset + OrgPiece->bit_size > Offset * 8) {
                LocationPiece * Piece = add_piece();
                *Piece = *OrgPiece;
                if (BitOffset < Offset * 8) {
                    Piece->bit_offs += Offset * 8 - BitOffset;
                    Piece->bit_size -= Offset * 8 - BitOffset;
                }
                if (Piece->bit_offs == 0 && Piece->bit_size % 8 == 0) {
                    Piece->size = Piece->bit_size / 8;
                    Piece->bit_size = 0;
                }
            }
            BitOffset += OrgPiece->bit_size;
        }
    }
    else if (PV.mAddr != NULL) {
        LocationPiece * Piece = add_piece();
        if (Offset > PV.mSize) str_exception(ERR_INV_DWARF, "Invalid OP_GNU_implicit_pointer");
        Piece->size = PV.mSize - Offset;
        Piece->value = PV.mAddr + Offset;
    }
    else if (PV.mForm == FORM_EXPR_VALUE) {
        sState->stk[sState->stk_pos++] = PV.mValue + Offset;
    }
    else {
        LocationPiece * Piece = add_piece();
        U1_T * Buf = (U1_T *)tmp_alloc(sizeof(PV.mValue));
        if (Offset > sizeof(PV.mValue)) str_exception(ERR_INV_DWARF, "Invalid OP_GNU_implicit_pointer");
        memcpy(Buf, &PV.mValue, sizeof(PV.mValue));
        if (big_endian_host() != PV.mBigEndian) swap_bytes(Buf, Piece->size);
        Piece->size = sizeof(PV.mValue) - Offset;
        Piece->value = Buf + Offset;
    }
    dio_EnterSection(&Unit->mDesc, sSection, DioPos);
}

static void evaluate_call(U8_T ID) {
    PropertyValue PV;
    U8_T DioPos = dio_GetPos();
    uint8_t * OrgCode = sState->code;
    size_t OrgCodePos = sState->code_pos;
    size_t OrgCodeLen = sState->code_len;
    ELF_Section * OrgSection = sSection;
    U8_T OrgSectionOffs = sSectionOffs;
    PropertyValue * OrgValue = sValue;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    ObjectInfo * Obj = find_object(get_dwarf_cache(Unit->mFile), ID);
    DWARFExpressionInfo Info;
    U8_T IP = 0;

    if (Obj == NULL) str_exception(ERR_INV_DWARF, "Invalid reference in OP_call");
    read_dwarf_object_property(sValue->mContext, sValue->mFrame, Obj, AT_location, &PV);

    sValue = &PV;

    if (sValue->mPieces != NULL || sValue->mAddr == NULL || sValue->mSize == 0) {
        str_exception(ERR_INV_DWARF, "Invalid DWARF expression reference");
    }
    if (sValue->mForm == FORM_DATA4 || sValue->mForm == FORM_DATA8) {
        if (sValue->mFrame == STACK_NO_FRAME) str_exception(ERR_INV_CONTEXT, "Need stack frame");
        if (read_reg_value(sState->stack_frame, get_PC_definition(sValue->mContext), &IP) < 0) exception(errno);
    }

    dwarf_find_expression(sValue, IP, &Info);
    sState->code = Info.expr_addr;
    sState->code_len = Info.expr_size;
    sState->code_pos = 0;
    sSection = Info.section;
    sSectionOffs = Info.expr_addr - (U1_T *)sSection->data;
    if (evaluate_vm_expression(sState) < 0) exception(errno);
    assert(sState->code_pos == sState->code_len);

    sState->code = OrgCode;
    sState->code_pos = OrgCodePos;
    sState->code_len = OrgCodeLen;
    sSection = OrgSection;
    sSectionOffs = OrgSectionOffs;
    sValue = OrgValue;
    dio_EnterSection(&Unit->mDesc, sSection, DioPos);
}

static void client_op(uint8_t op) {
    CompUnit * Unit = sValue->mObject->mCompUnit;
    dio_EnterSection(&Unit->mDesc, sSection, sSectionOffs + sState->code_pos);
    switch (op) {
    case OP_addr:
        sState->stk[sState->stk_pos++] = read_address();
        break;
    case OP_fbreg:
        if (sState->stack_frame == NULL) str_exception(ERR_INV_CONTEXT, "Invalid stack frame");
        sState->stk[sState->stk_pos++] = get_fbreg();
        break;
    case OP_form_tls_address:
        if (sState->stk_pos == 0) str_exception(ERR_INV_DWARF, "Invalid DWARF expression stack");
        sState->stk[sState->stk_pos - 1] = evaluate_tls_address(sState->stk[sState->stk_pos - 1]);
        break;
    case OP_GNU_push_tls_address:
        if (sState->stk_pos == 0 && sState->code_pos < sState->code_len) {
            /* This looks like a bug in GCC: offset sometimes is emitted after OP_GNU_push_tls_address */
            switch (dio_ReadU1()) {
            case OP_const4u: sState->stk[sState->stk_pos++] = dio_ReadU4(); break;
            case OP_const8u: sState->stk[sState->stk_pos++] = dio_ReadU8(); break;
            case OP_constu:  sState->stk[sState->stk_pos++] = dio_ReadU8LEB128(); break;
            }
        }
        if (sState->stk_pos == 0) str_exception(ERR_INV_DWARF, "Invalid DWARF expression stack");
        sState->stk[sState->stk_pos - 1] = evaluate_tls_address(sState->stk[sState->stk_pos - 1]);
        break;
    case OP_implicit_pointer:
    case OP_GNU_implicit_pointer:
        evaluate_implicit_pointer(op);
        break;
    case OP_call2:
        evaluate_call(Unit->mDesc.mSection->addr + Unit->mDesc.mUnitOffs + dio_ReadU2());
        break;
    case OP_call4:
        evaluate_call(Unit->mDesc.mSection->addr + Unit->mDesc.mUnitOffs + dio_ReadU4());
        break;
    case OP_call_ref:
        {
            ELF_Section * Section = NULL;
            int Size = Unit->mDesc.m64bit ? 8 : 4;
            if (Unit->mDesc.mVersion < 3) Size = Unit->mDesc.mAddressSize;
            evaluate_call(dio_ReadAddressX(&Section, Size));
        }
        break;
    default:
        str_fmt_exception(ERR_UNSUPPORTED, "Unsupported DWARF expression op 0x%02x", op);
    }
    sState->code_pos = (size_t)(dio_GetPos() - sSectionOffs);
    dio_ExitSection();
}

void dwarf_find_expression(PropertyValue * Value, U8_T IP, DWARFExpressionInfo * Info) {
    CompUnit * Unit = Value->mObject->mCompUnit;

    memset(Info, 0, sizeof(DWARFExpressionInfo));
    Info->object = Value->mObject;
    Info->unit = Unit;

    if (Value->mAddr == NULL || Value->mSize == 0) str_exception(ERR_INV_DWARF, "Invalid format of location expression");

    if (Value->mForm == FORM_DATA4 || Value->mForm == FORM_DATA8) {
        U8_T Base = 0;
        U8_T Offset = 0;
        U8_T AddrMax = ~(U8_T)0;
        DWARFCache * Cache = (DWARFCache *)Unit->mFile->dwarf_dt_cache;

        assert(Cache->magic == DWARF_CACHE_MAGIC);
        if (Cache->mDebugLoc == NULL) str_exception(ERR_INV_DWARF, "Missing .debug_loc section");
        dio_EnterSection(&Unit->mDesc, Unit->mDesc.mSection, Value->mAddr - (U1_T *)Unit->mDesc.mSection->data);
        Offset = dio_ReadUX(Value->mSize);
        dio_ExitSection();
        Base = Unit->mObject->u.mCode.mLowPC;
        if (Unit->mDesc.mAddressSize < 8) AddrMax = ((U8_T)1 << Unit->mDesc.mAddressSize * 8) - 1;
        dio_EnterSection(&Unit->mDesc, Cache->mDebugLoc, Offset);
        for (;;) {
            ELF_Section * S0 = NULL;
            ELF_Section * S1 = NULL;
            U8_T Addr0 = dio_ReadAddress(&S0);
            U8_T Addr1 = dio_ReadAddress(&S1);
            if (S0 == NULL) S0 = Unit->mTextSection;
            if (S1 == NULL) S1 = Unit->mTextSection;
            if (Addr0 == AddrMax) {
                Base = Addr1;
            }
            else if (Addr0 == 0 && Addr1 == 0) {
                break;
            }
            else if (S0 != S1 || Addr0 > Addr1) {
                str_exception(ERR_INV_DWARF, "Invalid .debug_loc section");
            }
            else {
                U2_T Size = dio_ReadU2();
                U8_T RTAddr0 = elf_map_to_run_time_address(Value->mContext, Unit->mFile, S0, (ContextAddress)(Base + Addr0));
                U8_T RTAddr1 = Addr1 - Addr0 + RTAddr0;
                if (RTAddr0 != 0 && IP >= RTAddr0 && IP < RTAddr1) {
                    Info->code_addr = RTAddr0;
                    Info->code_size = RTAddr1 - RTAddr0;
                    Info->section = Cache->mDebugLoc;
                    Info->expr_addr = dio_GetDataPtr();
                    Info->expr_size = Size;
                    dio_ExitSection();
                    return;
                }
                dio_Skip(Size);
            }
        }
        dio_ExitSection();
        str_exception(ERR_OTHER, "Object is not available at this location in the code");
    }
    else {
        Info->section = Unit->mDesc.mSection;
        Info->expr_addr = Value->mAddr;
        Info->expr_size = Value->mSize;
    }
}

void dwarf_evaluate_expression(PropertyValue * PV) {
    CompUnit * Unit = PV->mObject->mCompUnit;
    LocationExpressionState * OrgState = sState;
    ELF_Section * OrgSection = sSection;
    U8_T OrgSectionOffs = sSectionOffs;
    PropertyValue * OrgValue = sValue;
    DWARFExpressionInfo Info;
    U8_T IP = 0;
    U8_T args[2];

    sValue = PV;
    sStackFrame = sValue->mFrame;
    sState = (LocationExpressionState *)tmp_alloc_zero(sizeof(LocationExpressionState));
    sState->stk = (U8_T *)tmp_alloc(sizeof(U8_T) * (sState->stk_max = 8));
    sState->ctx = sValue->mContext;
    sState->stack_frame = get_stack_frame(PV);
    sState->addr_size = Unit->mDesc.mAddressSize;
    sState->reg_id_scope = Unit->mRegIdScope;
    sState->args = args;
    sState->client_op = client_op;
    args[0] = dwarf_expression_obj_addr;
    args[1] = dwarf_expression_pm_value;

    if (sValue->mAttr == AT_data_member_location) {
        sState->stk[sState->stk_pos++] = dwarf_expression_obj_addr;
        sState->args_cnt = 1;
    }
    if (sValue->mAttr == AT_use_location) {
        sState->stk[sState->stk_pos++] = dwarf_expression_pm_value;
        sState->stk[sState->stk_pos++] = dwarf_expression_obj_addr;
        sState->args_cnt = 2;
    }
    if (sValue->mPieces != NULL || sValue->mAddr == NULL || sValue->mSize == 0) {
        str_exception(ERR_INV_DWARF, "Invalid DWARF expression reference");
    }
    if (sValue->mForm == FORM_DATA4 || sValue->mForm == FORM_DATA8) {
        if (sValue->mFrame == STACK_NO_FRAME) str_exception(ERR_INV_CONTEXT, "Need stack frame");
        if (read_reg_value(sState->stack_frame, get_PC_definition(sValue->mContext), &IP) < 0) exception(errno);
    }

    dwarf_find_expression(sValue, IP, &Info);
    sState->code = Info.expr_addr;
    sState->code_len = Info.expr_size;
    sState->code_pos = 0;
    sSection = Info.section;
    sSectionOffs = Info.expr_addr - (U1_T *)sSection->data;
    if (evaluate_vm_expression(sState) < 0) exception(errno);
    assert(sState->code_pos == sState->code_len);

    sValue->mForm = FORM_EXPR_VALUE;
    sValue->mAddr = NULL;
    sValue->mValue = 0;
    sValue->mSize = 0;
    sValue->mBigEndian = sState->reg_id_scope.big_endian;
    sValue->mPieces = NULL;
    sValue->mPieceCnt = 0;

    if (sState->pieces_cnt) {
        sValue->mPieces = sState->pieces;
        sValue->mPieceCnt = sState->pieces_cnt;
    }
    else {
        sValue->mValue = sState->stk[--sState->stk_pos];
    }

    if (sState->stk_pos != 0) {
        str_exception(ERR_INV_DWARF, "Invalid DWARF expression stack");
    }

    sState = OrgState;
    sSection = OrgSection;
    sSectionOffs = OrgSectionOffs;
    sValue = OrgValue;
}

#endif /* ENABLE_ELF && ENABLE_DebugContext */
