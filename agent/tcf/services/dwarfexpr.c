/*******************************************************************************
 * Copyright (c) 2008, 2011 Wind River Systems, Inc. and others.
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

static VMState * sState = NULL;
static ELF_Section * sSection = NULL;
static U8_T sSectionOffs = 0;
static PropertyValue * sValue = NULL;
static PropertyValuePiece * sValuePieces = NULL;
static U4_T sValuePiecesCnt = 0;
static U4_T sValuePiecesMax = 0;

static PropertyValuePiece * add_piece(void) {
    PropertyValuePiece * Piece;
    if (sValuePiecesCnt >= sValuePiecesMax) {
        sValuePiecesMax += 8;
        sValuePieces = (PropertyValuePiece *)tmp_realloc(sValuePieces,
            sizeof(PropertyValuePiece) * sValuePiecesMax);
    }
    Piece = sValuePieces + sValuePiecesCnt++;
    memset(Piece, 0, sizeof(PropertyValuePiece));
    return Piece;
}

static StackFrame * get_stack_frame(PropertyValue * sValue) {
    StackFrame * Info = NULL;
    if (sValue->mFrame == STACK_NO_FRAME) return NULL;
    if (get_frame_info(sValue->mContext, sValue->mFrame, &Info) < 0) exception(errno);
    return Info;
}

static ObjectInfo * get_parent_function(ObjectInfo * Info) {
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
    if (addr == 0) str_exception(ERR_INV_ADDRESS, "Object has no RT address");
    return addr;
}

static U8_T get_fbreg(void) {
    PropertyValue FP;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    ObjectInfo * Parent = get_parent_function(sValue->mObject);
    U8_T addr = 0;

    if (Parent == NULL) str_exception(ERR_INV_DWARF, "OP_fbreg: no parent function");
    memset(&FP, 0, sizeof(FP));
    read_and_evaluate_dwarf_object_property(sState->ctx, sState->stack_frame, 0, Parent, AT_frame_base, &FP);

    if (FP.mRegister != NULL) {
        if (read_reg_value(get_stack_frame(&FP), FP.mRegister, &addr) < 0) exception(errno);
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

static void evaluate_implicit_pointer(void) {
    PropertyValue FP;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    ObjectInfo * Info = find_object(get_dwarf_cache(Unit->mFile), dio_ReadU4());
    U4_T Offset = dio_ReadULEB128();
    U8_T DioPos = dio_GetPos();
    if (Info == NULL) str_exception(ERR_INV_DWARF, "OP_GNU_implicit_pointer: invalid object reference");
    memset(&FP, 0, sizeof(FP));
    read_and_evaluate_dwarf_object_property(sState->ctx, sState->stack_frame, 0, Info, sValue->mAttr, &FP);
    if (FP.mPieces != NULL) {
        U4_T Cnt = 0;
        U4_T BitOffset = 0;
        while (Cnt < FP.mPieceCnt) {
            PropertyValuePiece * OrgPiece = FP.mPieces + Cnt++;
            if (BitOffset + OrgPiece->mBitSize > Offset * 8) {
                PropertyValuePiece * Piece = add_piece();
                *Piece = *OrgPiece;
                if (BitOffset < Offset * 8) {
                    Piece->mBitOffset += Offset * 8 - BitOffset;
                    Piece->mBitSize -= Offset * 8 - BitOffset;
                }
            }
            BitOffset += OrgPiece->mBitSize;
        }
    }
    else if (FP.mRegister != NULL) {
        PropertyValuePiece * Piece = add_piece();
        if (Offset > FP.mRegister->size) str_exception(ERR_INV_DWARF, "Invalid OP_GNU_implicit_pointer");
        Piece->mBigEndian = FP.mRegister->big_endian;
        Piece->mRegister = FP.mRegister;
        Piece->mBitOffset = Offset * 8;
        Piece->mBitSize = (FP.mRegister->size - Offset) * 8;
    }
    else if (FP.mAddr != NULL) {
        PropertyValuePiece * Piece = add_piece();
        if (Offset > FP.mSize) str_exception(ERR_INV_DWARF, "Invalid OP_GNU_implicit_pointer");
        Piece->mBigEndian = FP.mBigEndian;
        Piece->mValue = FP.mAddr;
        Piece->mBitOffset = Offset * 8;
        Piece->mBitSize = (FP.mSize - Offset) * 8;
    }
    else {
        PropertyValuePiece * Piece = add_piece();
        if (Offset > sizeof(FP.mValue)) str_exception(ERR_INV_DWARF, "Invalid OP_GNU_implicit_pointer");
        Piece->mBigEndian = big_endian_host();
        Piece->mValue = (U1_T *)tmp_alloc(sizeof(FP.mValue));
        Piece->mBitOffset = Offset * 8;
        Piece->mBitSize = (sizeof(FP.mValue) - Offset) * 8;
    }
    dio_EnterSection(&Unit->mDesc, sSection, DioPos);
}

static void client_op(uint8_t op) {
    dio_SetPos(sSectionOffs + sState->code_pos);
    switch (op) {
    case OP_addr:
        sState->stk[sState->stk_pos++] = read_address();
        break;
    case OP_fbreg:
        if (sState->stack_frame == STACK_NO_FRAME) str_exception(ERR_INV_CONTEXT, "Invalid stack frame");
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
    case OP_GNU_implicit_pointer:
        evaluate_implicit_pointer();
        break;
    default:
        str_fmt_exception(ERR_UNSUPPORTED, "Unsupported DWARF expression op 0x%02x", op);
    }
    sState->code_pos = (size_t)(dio_GetPos() - sSectionOffs);
}

static void evaluate_expression(ELF_Section * Section, U1_T * Buf, size_t Size) {
    int error = 0;
    CompUnit * Unit = sValue->mObject->mCompUnit;

    sState->code = Buf;
    sState->code_len = Size;
    sState->code_pos = 0;
    sSection = Section;
    sSectionOffs = Buf - (U1_T *)Section->data;
    dio_EnterSection(&Unit->mDesc, sSection, sSectionOffs);
    if (evaluate_vm_expression(sState) < 0) error = errno;
    if (!error && sState->piece_bits) {
        while (!error) {
            PropertyValuePiece * Piece = add_piece();
            if (sState->reg) {
                Piece->mRegister = sState->reg;
                Piece->mBigEndian = sState->reg->big_endian;
            }
            else if (sState->value_addr) {
                Piece->mValue = (U1_T *)sState->value_addr;
                if (sState->value_size * 8 < sState->piece_bits) str_exception(ERR_INV_DWARF, "Invalid object piece size");
                Piece->mBigEndian = sState->big_endian;
            }
            else if (sState->stk_pos == 0) {
                /* An empty location description represents a piece or all of an object that is
                 * present in the source but not in the object code (perhaps due to optimization). */
                size_t size = (sState->piece_bits + 7) / 8;
                Piece->mValue = (U1_T *)tmp_alloc_zero(size);
            }
            else {
                Piece->mAddress = sState->stk[--sState->stk_pos];
                Piece->mBigEndian = sState->big_endian;
            }
            Piece->mBitOffset = sState->piece_offs;
            Piece->mBitSize = sState->piece_bits;
            if (sState->stk_pos != 0) str_exception(ERR_INV_DWARF, "Invalid DWARF expression stack");
            if (sState->code_pos >= sState->code_len) break;
            if (evaluate_vm_expression(sState) < 0) error = errno;
        }
    }
    dio_ExitSection();
    assert(error || sState->code_pos == sState->code_len);
    if (error) exception(error);
}

static void evaluate_location(void) {
    U8_T IP = 0;
    U8_T Offset = 0;
    U8_T Base = 0;
    CompUnit * Unit = sValue->mObject->mCompUnit;
    DWARFCache * Cache = (DWARFCache *)Unit->mFile->dwarf_dt_cache;
    U8_T AddrMax = ~(U8_T)0;

    assert(Cache->magic == DWARF_CACHE_MAGIC);
    if (Cache->mDebugLoc == NULL) str_exception(ERR_INV_DWARF, "Missing .debug_loc section");
    dio_EnterSection(&Unit->mDesc, Unit->mDesc.mSection, sValue->mAddr - (U1_T *)Unit->mDesc.mSection->data);
    Offset = dio_ReadUX(sValue->mSize);
    dio_ExitSection();
    Base = Unit->mLowPC;
    if (Unit->mDesc.mAddressSize < 8) AddrMax = ((U8_T)1 << Unit->mDesc.mAddressSize * 8) - 1;
    if (read_reg_value(get_stack_frame(sValue), get_PC_definition(sValue->mContext), &IP) < 0) exception(errno);
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
            U8_T RTAddr0 = elf_map_to_run_time_address(sValue->mContext, Unit->mFile, S0, (ContextAddress)(Base + Addr0));
            U8_T RTAddr1 = Addr1 - Addr0 + RTAddr0;
            if (RTAddr0 != 0 && IP >= RTAddr0 && IP < RTAddr1) {
                U1_T * Buf = dio_GetDataPtr();
                dio_ExitSection();
                evaluate_expression(Cache->mDebugLoc, Buf, Size);
                return;
            }
            dio_Skip(Size);
        }
    }
    dio_ExitSection();
    str_exception(ERR_OTHER, "Object is not available at this location in the code");
}

void dwarf_evaluate_expression(U8_T BaseAddress, PropertyValue * v) {
    CompUnit * Unit = v->mObject->mCompUnit;
    VMState * OrgState = sState;
    ELF_Section * OrgSection = sSection;
    U8_T OrgSectionOffs = sSectionOffs;
    PropertyValue * OrgValue = sValue;
    PropertyValuePiece * OrgValuePieces = sValuePieces;
    U4_T OrgValuePiecesCnt = sValuePiecesCnt;
    U4_T OrgValuePiecesMax = sValuePiecesMax;

    sValue = v;
    sValuePieces = NULL;
    sValuePiecesCnt = 0;
    sValuePiecesMax = 0;
    sState = (VMState *)tmp_alloc_zero(sizeof(VMState));
    sState->ctx = sValue->mContext;
    sState->addr_size = Unit->mDesc.mAddressSize;
    sState->big_endian = Unit->mFile->big_endian;
    sState->stack_frame = sValue->mFrame;
    sState->reg_id_scope = Unit->mRegIdScope;
    sState->object_address = BaseAddress;
    sState->client_op = client_op;;

    if (sValue->mAttr == AT_data_member_location) {
        sState->stk = (U8_T *)tmp_alloc(sizeof(U8_T) * (sState->stk_max = 8));
        sState->stk[sState->stk_pos++] = BaseAddress;
    }
    if (sValue->mRegister != NULL || sValue->mAddr == NULL || sValue->mSize == 0) {
        str_exception(ERR_INV_DWARF, "Invalid DWARF expression reference");
    }
    if (sValue->mForm == FORM_DATA4 || sValue->mForm == FORM_DATA8) {
        if (sValue->mFrame == STACK_NO_FRAME) str_exception(ERR_INV_CONTEXT, "Need stack frame");
        evaluate_location();
    }
    else {
        evaluate_expression(Unit->mDesc.mSection, sValue->mAddr, sValue->mSize);
    }

    sValue->mForm = FORM_EXPR_VALUE;
    sValue->mAddr = NULL;
    sValue->mValue = 0;
    sValue->mSize = 0;
    sValue->mBigEndian = sState->big_endian;
    sValue->mRegister = NULL;
    sValue->mPieces = NULL;
    sValue->mPieceCnt = 0;

    if (sValuePieces) {
        sValue->mPieces = sValuePieces;
        sValue->mPieceCnt = sValuePiecesCnt;
    }
    else if (sState->reg) {
        sValue->mSize = sState->reg->size;
        sValue->mBigEndian = sState->reg->big_endian;
        sValue->mRegister = sState->reg;
    }
    else if (sState->value_addr) {
        sValue->mAddr = (U1_T *)sState->value_addr;
        sValue->mSize = sState->value_size;
        sValue->mBigEndian = sState->big_endian;
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
    sValuePieces = OrgValuePieces;
    sValuePiecesCnt = OrgValuePiecesCnt;
    sValuePiecesMax = OrgValuePiecesMax;
}

#endif /* ENABLE_ELF && ENABLE_DebugContext */
