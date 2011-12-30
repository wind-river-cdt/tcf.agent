/*******************************************************************************
 * Copyright (c) 2011 Wind River Systems, Inc. and others.
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
 * Transformation of DWARF expressions to a portable form.
 *
 * Functions in this module use exceptions to report errors, see exceptions.h
 */

#include <tcf/config.h>

#if ENABLE_ELF && ENABLE_DebugContext

#include <assert.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/dwarf.h>
#include <tcf/services/dwarfecomp.h>

static U1_T * buf = NULL;
static size_t buf_pos = 0;
static size_t buf_max = 0;
static DWARFExpressionInfo * expr = NULL;
static size_t expr_pos = 0;
static Context * expr_ctx = NULL;
static U8_T expr_ip = 0;

static void add(unsigned n) {
    if (buf_pos >= buf_max) {
        buf_max *= 2;
        buf = (U1_T *)tmp_realloc(buf, buf_max);
    }
    buf[buf_pos++] = (U1_T)n;
}

static void copy(size_t n) {
    while (n > 0) {
        if (expr_pos >= expr->expr_size) exception(ERR_INV_DWARF);
        add(expr->expr_addr[expr_pos++]);
        n--;
    }
}

static void copy_leb128(void) {
    for (;;) {
        U1_T n = expr->expr_addr[expr_pos++];
        add(n);
        if ((n & 0x80) == 0) break;
    }
}

static void add_uleb128(U8_T x) {
    for (;;) {
        U1_T n = (U1_T)(x & 0x7Fu);
        x = x >> 7;
        if (x == 0) {
            add(n);
            break;
        }
        add(n | 0x80u);
    }
}

#if 0
/* Not used yet */
static void add_sleb128(I8_T x) {
    for (;;) {
        U1_T n = (U1_T)(x & 0x7Fu);
        x = x >> 7;
        if (x == 0 || (x == 0xFFu && (n & 0x40))) {
            add(n);
            break;
        }
        add(n | 0x80u);
    }
}
#endif

static void add_expression(DWARFExpressionInfo * info);

static void op_addr(void) {
    ContextAddress addr = 0;
    ELF_Section * section = NULL;
    U8_T pos = 0;

    expr_pos++;
    pos = expr->expr_addr + expr_pos - (U1_T *)expr->section->data;
    dio_EnterSection(&expr->unit->mDesc, expr->section, pos);
    addr = (ContextAddress)dio_ReadAddress(&section);
    expr_pos += (size_t)(dio_GetPos() - pos);
    dio_ExitSection();
    addr = elf_map_to_run_time_address(expr_ctx, expr->unit->mFile, section, addr);
    if (errno) str_exception(errno, "Cannot get object run-time address");
    add(OP_constu);
    add_uleb128(addr);
}

static void op_fbreg(void) {
    PropertyValue fp;
    DWARFExpressionInfo info;
    ObjectInfo * parent = get_parent_function(expr->object);

    expr_pos++;
    memset(&fp, 0, sizeof(fp));
    if (parent == NULL) str_exception(ERR_INV_DWARF, "OP_fbreg: no parent function");
    read_dwarf_object_property(expr_ctx, STACK_NO_FRAME, parent, AT_frame_base, &fp);
    dwarf_find_expression(&fp, expr_ip, &info);
    switch (*info.expr_addr) {
    case OP_reg:
        add(OP_basereg);
        {
            unsigned i = 1;
            while (i < info.unit->mDesc.mAddressSize + 1u) {
                add(info.expr_addr[i++]);
            }
        }
        copy_leb128();
        return;
    case OP_regx:
        add(OP_bregx);
        {
            unsigned i = 1;
            for (;;) {
                U1_T n = info.expr_addr[i++];
                add(n);
                if ((n & 0x80) == 0) break;
            }
        }
        copy_leb128();
        return;
    case OP_reg0:
    case OP_reg1:
    case OP_reg2:
    case OP_reg3:
    case OP_reg4:
    case OP_reg5:
    case OP_reg6:
    case OP_reg7:
    case OP_reg8:
    case OP_reg9:
    case OP_reg10:
    case OP_reg11:
    case OP_reg12:
    case OP_reg13:
    case OP_reg14:
    case OP_reg15:
    case OP_reg16:
    case OP_reg17:
    case OP_reg18:
    case OP_reg19:
    case OP_reg20:
    case OP_reg21:
    case OP_reg22:
    case OP_reg23:
    case OP_reg24:
    case OP_reg25:
    case OP_reg26:
    case OP_reg27:
    case OP_reg28:
    case OP_reg29:
    case OP_reg30:
    case OP_reg31:
        add(OP_breg0 + (*info.expr_addr - OP_reg0));
        copy_leb128();
        return;
    }
    add_expression(&info);
    add(OP_consts);
    copy_leb128();
    add(OP_add);
}

static void add_expression(DWARFExpressionInfo * info) {
    DWARFExpressionInfo * org_expr = expr;
    size_t org_expr_pos = expr_pos;

    if (expr != NULL && info->code_size) {
        if (expr->code_size) {
            if (info->code_addr > expr->code_addr) {
                U8_T d = info->code_addr - expr->code_addr;
                assert(expr->code_size > d);
                expr->code_addr += d;
                expr->code_size -= d;
            }
            if (info->code_addr + info->code_size < expr->code_addr + expr->code_size) {
                U8_T d = (expr->code_addr + expr->code_size) - (info->code_addr + info->code_size);
                assert(expr->code_size > d);
                expr->code_size -= d;
            }
        }
        else {
            expr->code_addr = info->code_addr;
            expr->code_size = info->code_size;
        }
    }

    expr = info;
    expr_pos = 0;
    while (expr_pos < info->expr_size) {
        U1_T op = info->expr_addr[expr_pos];
        switch (op) {
        case OP_const1u:
        case OP_const1s:
        case OP_pick:
        case OP_deref_size:
        case OP_xderef_size:
            copy(2);
            break;
        case OP_const:
        case OP_reg:
        case OP_basereg:
            copy(1 + info->unit->mDesc.mAddressSize);
            break;
        case OP_const2u:
        case OP_const2s:
            copy(3);
            break;
        case OP_const4u:
        case OP_const4s:
            copy(5);
            break;
        case OP_const8u:
        case OP_const8s:
            copy(9);
            break;
        case OP_constu:
        case OP_consts:
        case OP_plus_uconst:
        case OP_regx:
        case OP_breg0:
        case OP_breg1:
        case OP_breg2:
        case OP_breg3:
        case OP_breg4:
        case OP_breg5:
        case OP_breg6:
        case OP_breg7:
        case OP_breg8:
        case OP_breg9:
        case OP_breg10:
        case OP_breg11:
        case OP_breg12:
        case OP_breg13:
        case OP_breg14:
        case OP_breg15:
        case OP_breg16:
        case OP_breg17:
        case OP_breg18:
        case OP_breg19:
        case OP_breg20:
        case OP_breg21:
        case OP_breg22:
        case OP_breg23:
        case OP_breg24:
        case OP_breg25:
        case OP_breg26:
        case OP_breg27:
        case OP_breg28:
        case OP_breg29:
        case OP_breg30:
        case OP_breg31:
        case OP_piece:
            add(op);
            expr_pos++;
            copy_leb128();
            break;
        case OP_bra:
        case OP_skip:
            str_exception(ERR_UNSUPPORTED, "OP_bra/OP_skip not supported yet");
            break;
        case OP_bregx:
        case OP_bit_piece:
            add(op);
            expr_pos++;
            copy_leb128();
            copy_leb128();
            break;
        case OP_implicit_value:
            {
                unsigned i = 0;
                size_t j = expr_pos + 1u;
                size_t size = 0;
                for (;; i += 7) {
                    U1_T n = info->expr_addr[j++];
                    size |= (n & 0x7Fu) << i;
                    if ((n & 0x80) == 0) break;
                }
                copy(j + size - expr_pos);
            }
            break;
        case OP_fbreg:
            op_fbreg();
            break;
        case OP_addr:
            op_addr();
            break;
        case OP_form_tls_address:
        case OP_GNU_push_tls_address:
        case OP_GNU_implicit_pointer:
        case OP_call2:
        case OP_call4:
        case OP_call_ref:
            str_fmt_exception(ERR_OTHER, "Unsupported DWARF expression op 0x%02x", op);
            break;
        default:
            add(op);
            expr_pos++;
            break;
        }
    }
    expr = org_expr;
    expr_pos = org_expr_pos;
}

void dwarf_transform_expression(Context * ctx, ContextAddress ip, DWARFExpressionInfo * info) {
    buf_pos = 0;
    buf_max = info->expr_size * 2;
    buf = (U1_T *)tmp_alloc(buf_max);
    expr_ctx = ctx;
    expr_ip = ip;
    expr = NULL;
    add_expression(info);
    info->expr_addr = buf;
    info->expr_size = buf_pos;
    buf_pos = 0;
    buf_max = 0;
    buf = NULL;
    expr = NULL;
    expr_pos = 0;
    expr_ctx = NULL;
    expr_ip = 0;
}

#endif
