/*******************************************************************************
 * Copyright (c) 2011, 2012 Wind River Systems, Inc. and others.
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
 * A virtual machine that executes DWARF expressions.
 */

#include <tcf/config.h>

#if ENABLE_DebugContext

#include <errno.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/dwarf.h>
#include <tcf/services/vm.h>

#define check_e_stack(n) { if (state->stk_pos < n) inv_dwarf("Invalid location expression stack"); }

static LocationExpressionState * state = NULL;
static RegisterDefinition * reg_def = NULL;
static void * value_addr = NULL;
static size_t value_size = 0;
static uint8_t * code = NULL;
static size_t code_pos = 0;
static size_t code_len = 0;

static void inv_dwarf(const char * msg) {
    str_exception(ERR_INV_DWARF, msg);
}

static uint64_t read_memory(uint64_t addr, size_t size) {
    size_t i;
    uint64_t n = 0;
    uint8_t buf[8];

    if (context_read_mem(state->ctx, (ContextAddress)addr, buf, size) < 0) exception(errno);
    for (i = 0; i < size; i++) {
        n = (n << 8) | buf[state->reg_id_scope.big_endian ? i : size - i - 1];
    }
    return n;
}

static uint8_t read_u1(void) {
    if (code_pos >= code_len) inv_dwarf("Invalid command");
    return code[code_pos++];
}

static uint16_t read_u2(void) {
    uint16_t x0 = read_u1();
    uint16_t x1 = read_u1();
    return state->reg_id_scope.big_endian ? (x0 << 8) | x1 : x0 | (x1 << 8);
}

static uint32_t read_u4(void) {
    uint32_t x0 = read_u2();
    uint32_t x1 = read_u2();
    return state->reg_id_scope.big_endian ? (x0 << 16) | x1 : x0 | (x1 << 16);
}

static uint64_t read_u8(void) {
    uint64_t x0 = read_u4();
    uint64_t x1 = read_u4();
    return state->reg_id_scope.big_endian ? (x0 << 32) | x1 : x0 | (x1 << 32);
}

static uint32_t read_u4leb128(void) {
    uint32_t res = 0;
    int i = 0;
    for (;; i += 7) {
        uint8_t n = read_u1();
        res |= (uint32_t)(n & 0x7Fu) << i;
        if ((n & 0x80) == 0) break;
    }
    return res;
}

static uint64_t read_u8leb128(void) {
    uint64_t res = 0;
    int i = 0;
    for (;; i += 7) {
        uint8_t n = read_u1();
        res |= (uint64_t)(n & 0x7Fu) << i;
        if ((n & 0x80) == 0) break;
    }
    return res;
}

static int64_t read_i8leb128(void) {
    uint64_t res = 0;
    int i = 0;
    for (;; i += 7) {
        uint8_t n = read_u1();
        res |= (uint64_t)(n & 0x7Fu) << i;
        if ((n & 0x80) == 0) {
            res |= -(int64_t)(n & 0x40) << i;
            break;
        }
    }
    return (int64_t)res;
}

static uint64_t read_ia(void) {
    switch (state->addr_size) {
    case 1: return (int8_t)read_u1();
    case 2: return (int16_t)read_u2();
    case 4: return (int32_t)read_u4();
    case 8: return (int64_t)read_u8();
    default: inv_dwarf("Invalid address size");
    }
    return 0;
}

static uint64_t read_ua(void) {
    switch (state->addr_size) {
    case 1: return read_u1();
    case 2: return read_u2();
    case 4: return read_u4();
    case 8: return read_u8();
    default: inv_dwarf("Invalid address size");
    }
    return 0;
}

static LocationPiece * add_piece(void) {
    LocationPiece * piece = NULL;
    if (state->pieces_cnt >= state->pieces_max) {
        state->pieces_max += 4;
        state->pieces = (LocationPiece *)tmp_realloc(state->pieces, state->pieces_max * sizeof(LocationPiece));
    }
    piece = state->pieces + state->pieces_cnt++;
    memset(piece, 0, sizeof(LocationPiece));
    if (reg_def != NULL) {
        piece->reg = reg_def;
        piece->size = reg_def->size;
    }
    else if (value_addr != NULL) {
        piece->value = value_addr;
        piece->size = value_size;
    }
    else if (state->stk_pos == 0) {
        /* An empty location description represents a piece or all of an object that is
         * present in the source but not in the object code (perhaps due to optimization). */
    }
    else {
        state->stk_pos--;
        piece->addr = (ContextAddress)state->stk[state->stk_pos];
    }
    reg_def = NULL;
    value_addr = NULL;
    return piece;
}

static void set_state(LocationExpressionState * s) {
    state = s;
    code = state->code;
    code_pos = state->code_pos;
    code_len = state->code_len;
    reg_def = NULL;
}

static void get_state(LocationExpressionState * s) {
    if (reg_def != NULL || value_addr != NULL) add_piece();
    s->code_pos = code_pos;
    state = NULL;
    code = NULL;
    code_pos = 0;
    code_len = 0;
}

static int is_end_of_loc_expr(void) {
    return
        code_pos >= code_len ||
        code[code_pos] == OP_piece ||
        code[code_pos] == OP_bit_piece ||
        code[code_pos] == OP_TCF_offset;
}

static void evaluate_expression(void) {
    uint64_t data = 0;

    if (code_len == 0) inv_dwarf("location expression size = 0");

    while (code_pos < code_len) {
        LocationPiece * piece = NULL;
        uint8_t op = code[code_pos++];

        if (state->stk_pos + 4 > state->stk_max) {
            state->stk_max += 8;
            state->stk = (uint64_t *)tmp_realloc(state->stk, sizeof(uint64_t) * state->stk_max);
        }

        switch (op) {
        case OP_deref:
            check_e_stack(1);
            state->stk[state->stk_pos - 1] = read_memory(state->stk[state->stk_pos - 1], state->addr_size);
            break;
        case OP_deref2:
            check_e_stack(1);
            state->stk[state->stk_pos - 1] = (int16_t)read_memory(state->stk[state->stk_pos - 1], 2);
            break;
        case OP_deref_size:
            check_e_stack(1);
            state->stk[state->stk_pos - 1] = read_memory(state->stk[state->stk_pos - 1], read_u1());
            break;
        case OP_const:
            state->stk[state->stk_pos++] = read_ia();
            break;
        case OP_const1u:
            state->stk[state->stk_pos++] = read_u1();
            break;
        case OP_const1s:
            state->stk[state->stk_pos++] = (int8_t)read_u1();
            break;
        case OP_const2u:
            state->stk[state->stk_pos++] = read_u2();
            break;
        case OP_const2s:
            state->stk[state->stk_pos++] = (int16_t)read_u2();
            break;
        case OP_const4u:
            state->stk[state->stk_pos++] = read_u4();
            break;
        case OP_const4s:
            state->stk[state->stk_pos++] = (int32_t)read_u4();
            break;
        case OP_const8u:
            state->stk[state->stk_pos++] = read_u8();
            break;
        case OP_const8s:
            state->stk[state->stk_pos++] = (int64_t)read_u8();
            break;
        case OP_constu:
            state->stk[state->stk_pos++] = read_u8leb128();
            break;
        case OP_consts:
            state->stk[state->stk_pos++] = read_i8leb128();
            break;
        case OP_dup:
            check_e_stack(1);
            state->stk[state->stk_pos] = state->stk[state->stk_pos - 1];
            state->stk_pos++;
            break;
        case OP_drop:
            check_e_stack(1);
            state->stk_pos--;
            break;
        case OP_over:
            check_e_stack(2);
            state->stk[state->stk_pos] = state->stk[state->stk_pos - 2];
            state->stk_pos++;
            break;
        case OP_pick:
            {
                unsigned n = read_u1();
                check_e_stack(n + 1);
                state->stk[state->stk_pos] = state->stk[state->stk_pos - n - 1];
                state->stk_pos++;
            }
            break;
        case OP_swap:
            check_e_stack(2);
            data = state->stk[state->stk_pos - 1];
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 2];
            state->stk[state->stk_pos - 2] = data;
            break;
        case OP_rot:
            check_e_stack(3);
            data = state->stk[state->stk_pos - 1];
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 2];
            state->stk[state->stk_pos - 2] = state->stk[state->stk_pos - 3];
            state->stk[state->stk_pos - 3] = data;
            break;
        case OP_xderef:
            check_e_stack(2);
            state->stk[state->stk_pos - 2] = read_memory(state->stk[state->stk_pos - 1], state->addr_size);
            state->stk_pos--;
            break;
        case OP_xderef_size:
            check_e_stack(2);
            state->stk[state->stk_pos - 2] = read_memory(state->stk[state->stk_pos - 1], read_u1());
            state->stk_pos--;
            break;
        case OP_abs:
            check_e_stack(1);
            if ((int64_t)state->stk[state->stk_pos - 1] < 0) {
                state->stk[state->stk_pos - 1] = ~state->stk[state->stk_pos - 1] + 1;
            }
            break;
        case OP_and:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] & state->stk[state->stk_pos];
            break;
        case OP_div:
            check_e_stack(2);
            state->stk_pos--;
            if (state->stk[state->stk_pos] == 0) inv_dwarf("Division by zero in location expression");
            state->stk[state->stk_pos - 1] /= state->stk[state->stk_pos];
            break;
        case OP_minus:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] -= state->stk[state->stk_pos];
            break;
        case OP_mod:
            check_e_stack(2);
            state->stk_pos--;
            if (state->stk[state->stk_pos] == 0) inv_dwarf("Division by zero in location expression");
            state->stk[state->stk_pos - 1] %= state->stk[state->stk_pos];
            break;
        case OP_mul:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] *= state->stk[state->stk_pos];
            break;
        case OP_neg:
            check_e_stack(1);
            state->stk[state->stk_pos - 1] = ~state->stk[state->stk_pos - 1] + 1;
            break;
        case OP_not:
            check_e_stack(1);
            state->stk[state->stk_pos - 1] = ~state->stk[state->stk_pos - 1];
            break;
        case OP_or:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] | state->stk[state->stk_pos];
            break;
        case OP_add:
        case OP_plus:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] += state->stk[state->stk_pos];
            break;
        case OP_plus_uconst:
            check_e_stack(1);
            state->stk[state->stk_pos - 1] += read_u8leb128();
            break;
        case OP_shl:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] <<= state->stk[state->stk_pos];
            break;
        case OP_shr:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] >>= state->stk[state->stk_pos];
            break;
        case OP_shra:
            {
                uint64_t cnt;
                check_e_stack(2);
                data = state->stk[state->stk_pos - 2];
                cnt = state->stk[state->stk_pos - 1];
                if (cnt >= 64) {
                    data = data & ((uint64_t)1 << 63) ? ~(uint64_t)0 : 0;
                }
                else {
                    while (cnt > 0) {
                        int s = (data & ((uint64_t)1 << 63)) != 0;
                        data >>= 1;
                        if (s) data |= (uint64_t)1 << 63;
                        cnt--;
                    }
                }
                state->stk[state->stk_pos - 2] = data;
                state->stk_pos--;
            }
            break;
        case OP_xor:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] ^ state->stk[state->stk_pos];
            break;
        case OP_bra:
            check_e_stack(1);
            {
                size_t offs = (int16_t)read_u2();
                if (state->stk[state->stk_pos - 1]) {
                    code_pos += offs;
                    if (code_pos > code_len) inv_dwarf("Invalid command");
                }
                state->stk_pos--;
            }
            break;
        case OP_eq:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] == state->stk[state->stk_pos];
            break;
        case OP_ge:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] >= state->stk[state->stk_pos];
            break;
        case OP_gt:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] > state->stk[state->stk_pos];
            break;
        case OP_le:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] <= state->stk[state->stk_pos];
            break;
        case OP_lt:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] < state->stk[state->stk_pos];
            break;
        case OP_ne:
            check_e_stack(2);
            state->stk_pos--;
            state->stk[state->stk_pos - 1] = state->stk[state->stk_pos - 1] != state->stk[state->stk_pos];
            break;
        case OP_skip:
            code_pos += (int16_t)read_u2();
            if (code_pos > code_len) inv_dwarf("Invalid command");
            break;
        case OP_lit0:
        case OP_lit1:
        case OP_lit2:
        case OP_lit3:
        case OP_lit4:
        case OP_lit5:
        case OP_lit6:
        case OP_lit7:
        case OP_lit8:
        case OP_lit9:
        case OP_lit10:
        case OP_lit11:
        case OP_lit12:
        case OP_lit13:
        case OP_lit14:
        case OP_lit15:
        case OP_lit16:
        case OP_lit17:
        case OP_lit18:
        case OP_lit19:
        case OP_lit20:
        case OP_lit21:
        case OP_lit22:
        case OP_lit23:
        case OP_lit24:
        case OP_lit25:
        case OP_lit26:
        case OP_lit27:
        case OP_lit28:
        case OP_lit29:
        case OP_lit30:
        case OP_lit31:
            state->stk[state->stk_pos++] = op - OP_lit0;
            break;
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
            {
                unsigned n = op - OP_reg0;
                if (!is_end_of_loc_expr()) inv_dwarf("OP_reg* must be last instruction");
                reg_def = get_reg_by_id(state->ctx, n, &state->reg_id_scope);
                if (reg_def == NULL) exception(errno);
            }
            break;
        case OP_regx:
            {
                unsigned n = (unsigned)read_u4leb128();
                if (!is_end_of_loc_expr()) inv_dwarf("OP_regx must be last instruction");
                reg_def = get_reg_by_id(state->ctx, n, &state->reg_id_scope);
                if (reg_def == NULL) exception(errno);
            }
            break;
        case OP_reg:
            {
                unsigned n = (unsigned)read_ua();
                if (!is_end_of_loc_expr()) inv_dwarf("OP_reg must be last instruction");
                reg_def = get_reg_by_id(state->ctx, n, &state->reg_id_scope);
                if (reg_def == NULL) exception(errno);
            }
            break;
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
            {
                RegisterDefinition * def = get_reg_by_id(state->ctx, op - OP_breg0, &state->reg_id_scope);
                if (def == NULL) exception(errno);
                if (read_reg_value(state->stack_frame, def, state->stk + state->stk_pos) < 0) exception(errno);
                state->stk[state->stk_pos++] += read_i8leb128();
            }
            break;
        case OP_bregx:
            {
                RegisterDefinition * def = get_reg_by_id(state->ctx, (unsigned)read_u4leb128(), &state->reg_id_scope);
                if (def == NULL) exception(errno);
                if (read_reg_value(state->stack_frame, def, state->stk + state->stk_pos) < 0) exception(errno);
                state->stk[state->stk_pos++] += read_i8leb128();
            }
            break;
        case OP_basereg:
            {
                RegisterDefinition * def = get_reg_by_id(state->ctx, (unsigned)read_ua(), &state->reg_id_scope);
                if (def == NULL) exception(errno);
                if (read_reg_value(state->stack_frame, def, state->stk + state->stk_pos) < 0) exception(errno);
                state->stk_pos++;
            }
            break;
        case OP_call_frame_cfa:
            {
                StackFrame * frame = state->stack_frame;
                if (frame == NULL) str_exception(ERR_INV_ADDRESS, "Stack frame address not available");
                state->stk[state->stk_pos++] = frame->fp;
            }
            break;
        case OP_nop:
            break;
        case OP_push_object_address:
            if (state->args_cnt == 0) str_exception(ERR_INV_ADDRESS, "Invalid address of containing object");
            state->stk[state->stk_pos++] = state->args[0];
            break;
        case OP_piece:
            piece = add_piece();
            piece->size = read_u4leb128();
            break;
        case OP_bit_piece:
            piece = add_piece();
            piece->bit_size = read_u4leb128();
            piece->bit_offs = read_u4leb128();
            break;
        case OP_implicit_value:
            value_size = read_u4leb128();
            if (code_pos + value_size > code_len) inv_dwarf("Invalid command");
            value_addr = tmp_alloc(value_size);
            memcpy(value_addr, code + code_pos, value_size);
            code_pos += value_size;
            if (!is_end_of_loc_expr()) inv_dwarf("OP_implicit_value must be last instruction");
            break;
        case OP_stack_value:
            check_e_stack(1);
            value_size = state->addr_size;
            value_addr = tmp_alloc(value_size);
            {
                unsigned i;
                uint8_t * buf = (uint8_t *)value_addr;
                uint64_t n = state->stk[--state->stk_pos];
                for (i = 0; i < value_size; i++) {
                    buf[state->reg_id_scope.big_endian ? value_size - i - 1 : i] = (uint8_t)n;
                    n >>= 8;
                }
            }
            if (!is_end_of_loc_expr()) inv_dwarf("OP_stack_value must be last instruction");
            break;
        case OP_TCF_offset:
            if (reg_def != NULL || value_addr != NULL) add_piece();
            if (state->pieces) {
                unsigned cnt = 0;
                uint32_t bit_offs = 0;
                uint32_t offs = read_u4leb128();
                LocationPiece * pieces = state->pieces;
                unsigned pieces_cnt = state->pieces_cnt;
                state->pieces = NULL;
                state->pieces_cnt = state->pieces_max = 0;
                while (cnt < pieces_cnt) {
                    LocationPiece * org_piece = pieces + cnt++;
                    if (org_piece->bit_size == 0) org_piece->bit_size = org_piece->size * 8;
                    if (bit_offs + org_piece->bit_size > offs * 8) {
                        LocationPiece * piece = NULL;
                        if (state->pieces_cnt >= state->pieces_max) {
                            state->pieces_max += 4;
                            state->pieces = (LocationPiece *)tmp_realloc(state->pieces, state->pieces_max * sizeof(LocationPiece));
                        }
                        piece = state->pieces + state->pieces_cnt++;
                        *piece = *org_piece;
                        if (bit_offs < offs * 8) {
                            piece->bit_offs += offs * 8 - bit_offs;
                            piece->bit_size -= offs * 8 - bit_offs;
                        }
                        if (piece->bit_offs == 0 && piece->bit_size % 8 == 0) {
                            piece->size = piece->bit_size / 8;
                            piece->bit_size = 0;
                        }
                    }
                    bit_offs += org_piece->bit_size;
                }
            }
            else {
                check_e_stack(1);
                state->stk[state->stk_pos - 1] += read_u8leb128();
            }
            break;
        case OP_GNU_entry_value:
            {
                LocationExpressionState * s = state;
                LocationExpressionState entry_state;
                int frame = get_prev_frame(s->ctx, get_info_frame(s->ctx, s->stack_frame));
                uint32_t size = read_u4leb128();
                get_state(s);
                memset(&entry_state, 0, sizeof(entry_state));
                entry_state.ctx = s->ctx;
                if (get_frame_info(s->ctx, frame, &entry_state.stack_frame) < 0) exception(errno);
                entry_state.reg_id_scope = s->reg_id_scope;
                entry_state.addr_size = s->addr_size;
                entry_state.code = s->code + s->code_pos;
                entry_state.code_len = size;
                entry_state.client_op = s->client_op;
                if (evaluate_vm_expression(&entry_state) < 0) exception(errno);
                if (entry_state.pieces_cnt > 0) {
                    size_t i;
                    uint64_t value = 0;
                    void * value_addr = NULL;
                    size_t value_size = 0;
                    read_location_pieces(entry_state.ctx, entry_state.stack_frame,
                        entry_state.pieces, entry_state.pieces_cnt, 0,
                        &value_addr, &value_size);
                    if (value_size > sizeof(value)) inv_dwarf("Invalid OP_entry_value expression");
                    for (i = 0; i < value_size; i++) {
                        value |= ((uint8_t *)value_addr)[i] << (i * 8);
                    }
                    s->stk[s->stk_pos++] = value;
                }
                else if (entry_state.stk_pos == 1) {
                    s->stk[s->stk_pos++] = entry_state.stk[entry_state.stk_pos - 1];
                }
                else {
                    inv_dwarf("Invalid OP_entry_value expression");
                }
                s->code_pos += size;
                set_state(s);
            }
            break;
        case OP_call2:
        case OP_call4:
        case OP_call_ref:
        default:
            {
                LocationExpressionState * s = state;
                get_state(s);
                s->client_op(op);
                set_state(s);
            }
        }
    }
}

int evaluate_vm_expression(LocationExpressionState * vm_state) {
    int error = 0;
    Trap trap;

    set_state(vm_state);
    if (set_trap(&trap)) {
        evaluate_expression();
        clear_trap(&trap);
    }
    else {
        error = trap.error;
    }
    get_state(vm_state);
    if (!error) return 0;
    errno = error;
    return -1;
}

#endif /* ENABLE_DebugContext */
