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
#include <tcf/services/elf-loader.h>

typedef struct JumpInfo {
    U1_T op;
    I2_T delta;
    I2_T jump_offs;
    size_t size;
    size_t src_pos;
    size_t dst_pos;
    struct JumpInfo * next;
} JumpInfo;

static U1_T * buf = NULL;
static size_t buf_pos = 0;
static size_t buf_max = 0;
static JumpInfo * jumps = NULL;
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
    if (expr_pos < expr->expr_size && expr->expr_addr[expr_pos] == OP_GNU_push_tls_address) {
        /* Bug in some versions of GCC: OP_addr used instead of OP_const, don't relocate */
    }
    else {
        addr = elf_map_to_run_time_address(expr_ctx, expr->unit->mFile, section, addr);
        if (errno) str_exception(errno, "Cannot get object run-time address");
    }
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

static void op_implicit_pointer(void) {
    Trap trap;
    PropertyValue pv;
    DWARFExpressionInfo info;
    U1_T op = expr->expr_addr[expr_pos];
    CompUnit * unit = expr->object->mCompUnit;
    int arg_size = unit->mDesc.m64bit ? 8 : 4;
    ObjectInfo * ref_obj = NULL;
    ContextAddress ref_id = 0;
    U4_T offset = 0;
    U8_T dio_pos = 0;

    expr_pos++;
    if (op == OP_GNU_implicit_pointer && unit->mDesc.mVersion < 3) arg_size = unit->mDesc.mAddressSize;
    dio_pos = expr->expr_addr + expr_pos - (U1_T *)expr->section->data;
    dio_EnterSection(&expr->unit->mDesc, expr->section, dio_pos);
    ref_id = dio_ReadUX(arg_size);
    offset = dio_ReadULEB128();
    expr_pos += (size_t)(dio_GetPos() - dio_pos);
    dio_ExitSection();

    ref_obj = find_object(get_dwarf_cache(unit->mFile), ref_id);
    if (ref_obj == NULL) str_exception(ERR_INV_DWARF, "OP_implicit_pointer: invalid object reference");

    memset(&pv, 0, sizeof(pv));
    if (set_trap(&trap)) {
        read_dwarf_object_property(expr_ctx, STACK_NO_FRAME, ref_obj, AT_location, &pv);
        clear_trap(&trap);
    }
    else if (trap.error == ERR_SYM_NOT_FOUND) {
        read_dwarf_object_property(expr_ctx, STACK_NO_FRAME, ref_obj, AT_const_value, &pv);
    }
    else {
        exception(trap.error);
    }
    dwarf_find_expression(&pv, expr_ip, &info);
    add_expression(&info);
    if (offset != 0) {
        add(OP_TCF_offset);
        add_uleb128(offset);
    }
}

static void op_push_tls_address(void) {
    U8_T addr = 0;
    expr_pos++;
    if (expr_pos == 1 && expr_pos < expr->expr_size) {
        /* This looks like a bug in GCC: offset sometimes is emitted after OP_GNU_push_tls_address */
        U1_T op = expr->expr_addr[expr_pos];
        switch (op) {
        case OP_const4u: copy(5); break;
        case OP_const8u: copy(9); break;
        case OP_constu:  add(op); expr_pos++; copy_leb128(); break;
        }
    }
    if (!context_has_state(expr_ctx)) str_exception(ERR_INV_CONTEXT,
        "Thread local variable, but context is not a thread");
    addr = get_tls_address(expr_ctx, expr->object->mCompUnit->mFile);
    if (addr != 0) {
        add(OP_constu);
        add_uleb128(addr);
        add(OP_add);
    }
}

static void op_call() {
    U8_T ref_id = 0;
    DIO_UnitDescriptor * desc = &expr->unit->mDesc;
    U8_T dio_pos = expr->expr_addr + expr_pos - (U1_T *)expr->section->data;
    ObjectInfo * ref_obj = NULL;
    DWARFExpressionInfo info;
    PropertyValue pv;

    dio_EnterSection(desc, expr->section, dio_pos);
    switch (expr->expr_addr[expr_pos]) {
    case OP_call2:
        ref_id = desc->mSection->addr + desc->mUnitOffs + dio_ReadU2();
        break;
    case OP_call4:
        ref_id = desc->mSection->addr + desc->mUnitOffs + dio_ReadU4();
        break;
    case OP_call_ref:
        {
            ELF_Section * section = NULL;
            int size = desc->m64bit ? 8 : 4;
            if (desc->mVersion < 3) size = desc->mAddressSize;
            ref_id = dio_ReadAddressX(&section, size);
        }
        break;
    }
    expr_pos += (size_t)(dio_GetPos() - dio_pos);
    dio_ExitSection();

    ref_obj = find_object(get_dwarf_cache(expr->unit->mFile), ref_id);
    if (ref_obj == NULL) str_exception(ERR_INV_DWARF, "Invalid reference in OP_call");
    read_dwarf_object_property(expr_ctx, STACK_NO_FRAME, ref_obj, AT_location, &pv);
    dwarf_find_expression(&pv, expr_ip, &info);
    add_expression(&info);
}

static void adjust_jumps(void) {
    JumpInfo * i = jumps;
    while (i != NULL) {
        if (i->op == OP_bra || i->op == OP_skip) {
            int delta = 0;
            JumpInfo * j = jumps;
            while (j != NULL) {
                if (i->jump_offs > 0) {
                    if (j->src_pos > i->src_pos && j->src_pos < i->src_pos + i->jump_offs) {
                        delta += j->delta;
                    }
                }
                else {
                    if (j->src_pos > i->src_pos + i->jump_offs && j->src_pos < i->src_pos) {
                        delta -= j->delta;
                    }
                }
                j = j->next;
            }
            if (delta != 0) {
                U2_T new_offs = (U2_T)(i->jump_offs + delta);
                if (expr->unit->mFile->big_endian) {
                    buf[i->dst_pos + 1] = (U1_T)((new_offs >> 8) & 0xffu);
                    buf[i->dst_pos + 2] = (U1_T)(new_offs & 0xffu);
                }
                else {
                    buf[i->dst_pos + 1] = (U1_T)(new_offs & 0xffu);
                    buf[i->dst_pos + 2] = (U1_T)((new_offs >> 8) & 0xffu);
                }
            }
        }
        i = i->next;
    }
}

static void add_expression(DWARFExpressionInfo * info) {
    DWARFExpressionInfo * org_expr = expr;
    size_t org_expr_pos = expr_pos;
    JumpInfo * org_jumps = jumps;

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
    jumps = NULL;
    while (expr_pos < info->expr_size) {
        size_t op_src_pos = expr_pos;
        size_t op_dst_pos = buf_pos;
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
            {
                U2_T x0 = info->expr_addr[expr_pos + 1];
                U2_T x1 = info->expr_addr[expr_pos + 2];
                U2_T offs = expr->unit->mFile->big_endian ? (x0 << 8) | x1 : x0 | (x1 << 8);
                if (offs != 0) {
                    JumpInfo * i = (JumpInfo *)tmp_alloc_zero(sizeof(JumpInfo));
                    i->op = op;
                    i->jump_offs = (I2_T)offs;
                    i->src_pos = op_src_pos;
                    i->dst_pos = op_dst_pos;
                    i->next = jumps;
                    jumps = i;
                    copy(3);
                }
            }
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
        case OP_implicit_pointer:
        case OP_GNU_implicit_pointer:
            op_implicit_pointer();
            break;
        case OP_form_tls_address:
        case OP_GNU_push_tls_address:
            op_push_tls_address();
            break;
        case OP_call2:
        case OP_call4:
        case OP_call_ref:
            op_call();
            break;
        default:
            if (op >= OP_lo_user) {
                str_fmt_exception(ERR_OTHER, "Unsupported DWARF expression op 0x%02x", op);
            }
            add(op);
            expr_pos++;
            break;
        }
        if (buf_pos - op_dst_pos != expr_pos - op_src_pos) {
            JumpInfo * i = (JumpInfo *)tmp_alloc_zero(sizeof(JumpInfo));
            i->op = op;
            i->delta = (I2_T)(buf_pos - op_dst_pos) - (I2_T)(expr_pos - op_src_pos);
            i->src_pos = op_src_pos;
            i->dst_pos = op_dst_pos;
            i->next = jumps;
            jumps = i;
        }
    }
    adjust_jumps();
    expr = org_expr;
    expr_pos = org_expr_pos;
    jumps = org_jumps;
}

void dwarf_transform_expression(Context * ctx, ContextAddress ip, DWARFExpressionInfo * info) {
    buf_pos = 0;
    buf_max = info->expr_size * 2;
    buf = (U1_T *)tmp_alloc(buf_max);
    expr_ctx = ctx;
    expr_ip = ip;
    expr = NULL;
    jumps = NULL;
    add_expression(info);
    info->expr_addr = buf;
    info->expr_size = buf_pos;
    buf_pos = 0;
    buf_max = 0;
    buf = NULL;
    jumps = NULL;
    expr = NULL;
    expr_pos = 0;
    expr_ctx = NULL;
    expr_ip = 0;
}

#endif
