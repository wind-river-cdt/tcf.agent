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
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/errors.h>
#include <tcf/services/dwarf.h>
#include <tcf/services/dwarfexpr.h>
#include <tcf/services/dwarfecomp.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/vm.h>

U8_T dwarf_expression_obj_addr = 0;
U8_T dwarf_expression_pm_value = 0;

static U8_T map_to_link_time_address(Context * ctx, CompUnit * Unit, U8_T Addr, ELF_Section ** SecPtr) {
    ELF_File * File = NULL;
    ELF_Section * Sec = NULL;
    Addr = elf_map_to_link_time_address(ctx, Addr, &File, &Sec);
    if (File == NULL || get_dwarf_file(File) != Unit->mFile)
        str_exception(ERR_INV_DWARF, "Object location info not available");
    if (Sec != NULL && Sec->file != Unit->mFile) {
        unsigned i;
        for (i = 1; i < Unit->mFile->section_cnt; i++) {
            ELF_Section * S = Unit->mFile->sections + i;
            if (S->name == NULL) continue;
            if (strcmp(S->name, Sec->name) == 0) {
                Sec = S;
                break;
            }
        }
    }
    *SecPtr = Sec;
    return Addr;
}

void dwarf_find_expression(PropertyValue * Value, U8_T IP, DWARFExpressionInfo * Info) {
    CompUnit * Unit = Value->mObject->mCompUnit;

    memset(Info, 0, sizeof(DWARFExpressionInfo));
    Info->object = Value->mObject;
    Info->unit = Unit;

    if (Value->mAddr == NULL || Value->mSize == 0) str_exception(ERR_INV_DWARF, "Invalid format of location expression");

    if (Value->mForm == FORM_DATA4 || Value->mForm == FORM_DATA8 || Value->mForm == FORM_SEC_OFFSET) {
        U8_T Base = 0;
        U8_T Offset = 0;
        U8_T AddrMax = ~(U8_T)0;
        DWARFCache * Cache = (DWARFCache *)Unit->mFile->dwarf_dt_cache;
        ELF_Section * IP_Sec = NULL;
        U8_T LT_IP = map_to_link_time_address(Value->mContext, Unit, IP, &IP_Sec);

        assert(Cache->magic == DWARF_CACHE_MAGIC);
        if (Cache->mDebugLoc == NULL) str_exception(ERR_INV_DWARF, "Missing .debug_loc section");
        dio_EnterSection(&Unit->mDesc, Unit->mDesc.mSection, Value->mAddr - (U1_T *)Unit->mDesc.mSection->data);
        Offset = dio_ReadAddressX(NULL, Value->mSize);
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
            else if (Addr0 > Addr1) {
                str_exception(ERR_INV_DWARF, "Invalid .debug_loc section");
            }
            else {
                U2_T Size = dio_ReadU2();
                if (LT_IP >= Base + Addr0 && LT_IP < Base + Addr1 &&
                        (IP_Sec == NULL || S0 == NULL || IP_Sec == S0) &&
                        (IP_Sec == NULL || S1 == NULL || IP_Sec == S1)) {
                    Info->code_addr = Base + Addr0 - LT_IP + IP;
                    Info->code_size = Addr1 - Addr0;
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

void dwarf_evaluate_expression(PropertyValue * Value) {
    CompUnit * Unit = Value->mObject->mCompUnit;
    LocationExpressionState * State = NULL;
    DWARFExpressionInfo Info;
    U8_T IP = 0;
    U8_T args[2];

    State = (LocationExpressionState *)tmp_alloc_zero(sizeof(LocationExpressionState));
    State->stk = (U8_T *)tmp_alloc(sizeof(U8_T) * (State->stk_max = 8));
    State->ctx = Value->mContext;
    if (Value->mFrame != STACK_NO_FRAME &&
            get_frame_info(Value->mContext, Value->mFrame, &State->stack_frame) < 0)
        exception(errno);
    State->addr_size = Unit->mDesc.mAddressSize;
    State->reg_id_scope = Unit->mRegIdScope;
    State->args = args;
    args[0] = dwarf_expression_obj_addr;
    args[1] = dwarf_expression_pm_value;

    if (Value->mAttr == AT_data_member_location) {
        State->stk[State->stk_pos++] = dwarf_expression_obj_addr;
        State->args_cnt = 1;
    }
    if (Value->mAttr == AT_use_location) {
        State->stk[State->stk_pos++] = dwarf_expression_pm_value;
        State->stk[State->stk_pos++] = dwarf_expression_obj_addr;
        State->args_cnt = 2;
    }
    if (Value->mPieces != NULL || Value->mAddr == NULL || Value->mSize == 0) {
        str_exception(ERR_INV_DWARF, "Invalid DWARF expression reference");
    }
    if (Value->mForm == FORM_DATA4 || Value->mForm == FORM_DATA8) {
        if (Value->mFrame == STACK_NO_FRAME) str_exception(ERR_INV_CONTEXT, "Need stack frame");
        if (read_reg_value(State->stack_frame, get_PC_definition(Value->mContext), &IP) < 0) exception(errno);
    }

    dwarf_find_expression(Value, IP, &Info);
    dwarf_transform_expression(Value->mContext, IP, Value->mFrame == STACK_NO_FRAME, &Info);
    State->code = Info.expr_addr;
    State->code_len = Info.expr_size;
    State->code_pos = 0;
    if (evaluate_vm_expression(State) < 0) exception(errno);
    assert(State->code_pos == State->code_len);

    Value->mForm = FORM_EXPR_VALUE;
    Value->mAddr = NULL;
    Value->mValue = 0;
    Value->mSize = 0;
    Value->mBigEndian = State->reg_id_scope.big_endian;
    Value->mPieces = NULL;
    Value->mPieceCnt = 0;

    if (State->pieces_cnt) {
        Value->mPieces = State->pieces;
        Value->mPieceCnt = State->pieces_cnt;
    }
    else {
        Value->mValue = State->stk[--State->stk_pos];
    }

    if (State->stk_pos != 0) {
        str_exception(ERR_INV_DWARF, "Invalid DWARF expression stack");
    }
}

#endif /* ENABLE_ELF && ENABLE_DebugContext */
