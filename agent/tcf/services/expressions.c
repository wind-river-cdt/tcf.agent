/*******************************************************************************
 * Copyright (c) 2007, 2012 Wind River Systems, Inc. and others.
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
 * Expression evaluation service.
 *
 * Extensions to regular C/C++ syntax:
 * 1. Special characters in identifiers: $"X", or just "X" if followed by ::
 *    where X is object name that can contain any characters.
 * 2. Symbol IDs in expressions: ${X}
 *    where X is symbol ID as returned by symbols service.
 * 3. CPU registers: $X
 *    where X is a register name, e.g. $ax
 */

#include <tcf/config.h>

#if SERVICE_Expressions

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/json.h>
#include <tcf/framework/cache.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/context.h>
#include <tcf/services/runctrl.h>
#include <tcf/services/symbols.h>
#include <tcf/services/funccall.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/memoryservice.h>
#include <tcf/services/breakpoints.h>
#include <tcf/services/registers.h>
#include <tcf/services/expressions.h>
#include <tcf/main/test.h>

#define SY_LEQ   256
#define SY_GEQ   257
#define SY_EQU   258
#define SY_NEQ   259
#define SY_AND   260
#define SY_OR    261
#define SY_SHL   262
#define SY_SHR   263
#define SY_VAL   264
#define SY_ID    265
#define SY_REF   266
#define SY_DEC   267
#define SY_INC   268
#define SY_A_SUB 269
#define SY_A_ADD 270
#define SY_A_SHL 271
#define SY_A_SHR 272
#define SY_A_OR  273
#define SY_A_XOR 274
#define SY_A_AND 275
#define SY_A_MUL 276
#define SY_A_DIV 277
#define SY_A_MOD 278
#define SY_SIZEOF 279
#define SY_NAME  280
#define SY_SCOPE 281
#define SY_PM_D  282
#define SY_PM_R  283

#define MODE_NORMAL 0
#define MODE_TYPE   1
#define MODE_SKIP   2

static char * text = NULL;
static int text_pos = 0;
static int text_len = 0;
static int text_ch = 0;
static int text_sy = 0;
static int sy_pos = 0;
static Value text_val;

/* Host endianness */
static int big_endian = 0;

static Context * expression_context = NULL;
static int expression_frame = STACK_NO_FRAME;
static ContextAddress expression_addr = 0;
static int expression_has_func_call = 0;

#ifndef ENABLE_FuncCallInjection
#  define ENABLE_FuncCallInjection (ENABLE_Symbols && SERVICE_RunControl && SERVICE_Breakpoints && ENABLE_DebugContext)
#endif

#if ENABLE_FuncCallInjection
typedef struct FuncCallState {
    LINK link_all;
    unsigned id;            /* ACPM transaction ID */
    int pos;                /* Text position in the expression */
    int started;            /* Target has started to execute the function call */
    int intercepted;        /* Intercepted during or after the function call */
    int committed;          /* ACPM transaction finished */
    int finished;           /* Target has finished the function call */
    Context * ctx;
    uint64_t ret_addr;
    ContextAddress stk_addr;
    ContextAddress func_addr;
    AbstractCache cache;
    BreakpointInfo * bp;
    ErrorReport * error;

    /* Actual arguments */
    Value * args;
    unsigned args_cnt;
    unsigned args_max;

    /* Returned value */
    void * ret_value;
    size_t ret_size;
    int ret_big_endian;

    /* After call commands */
    LocationExpressionCommand * cmds;
    unsigned cmds_cnt;

    /* Saved registers */
    RegisterDefinition ** regs;
    unsigned regs_cnt;
    uint8_t * regs_data;
} FuncCallState;

static LINK func_call_state = TCF_LIST_INIT(func_call_state);

#define link_all2fc(A)  ((FuncCallState *)((char *)(A) - offsetof(FuncCallState, link_all)))

#endif /* ENABLE_FuncCallInjection */

#define MAX_ID_CALLBACKS 8
static ExpressionIdentifierCallBack * id_callbacks[MAX_ID_CALLBACKS];
static int id_callback_cnt = 0;

void set_value(Value * v, void * data, size_t size, int big_endian) {
    v->sym = NULL;
    v->reg = NULL;
    v->remote = 0;
    v->address = 0;
    v->function = 0;
    v->size = (ContextAddress)size;
    v->big_endian = big_endian;
    v->value = tmp_alloc(size);
    if (data == NULL) memset(v->value, 0, size);
    else memcpy(v->value, data, size);
}

static void set_int_value(Value * v, size_t size, uint64_t n) {
    union {
        uint8_t  u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    } buf;
    switch (size) {
    case 1: buf.u8 = (uint8_t)n; break;
    case 2: buf.u16 = (uint16_t)n; break;
    case 4: buf.u32 = (uint32_t)n; break;
    case 8: buf.u64 = n; break;
    default: assert(0);
    }
    set_value(v, &buf, size, big_endian);
}

static void set_fp_value(Value * v, size_t size, double n) {
    union {
        float  f;
        double d;
    } buf;
    switch (size) {
    case 4: buf.f = (float)n; break;
    case 8: buf.d = n; break;
    default: assert(0);
    }
    set_value(v, &buf, size, big_endian);
}

static void set_ctx_word_value(Value * v, ContextAddress data) {
    set_int_value(v, context_word_size(expression_context), data);
}

static void set_string_value(Value * v, char * str) {
    v->type_class = TYPE_CLASS_ARRAY;
    if (str != NULL) set_value(v, str, strlen(str) + 1, 0);
}

static void error(int no, const char * fmt, ...) {
    va_list ap;
    char buf[256];
    size_t l = 0;

    va_start(ap, fmt);
    l = snprintf(buf, sizeof(buf), "At col %d: ", sy_pos);
    vsnprintf(buf + l, sizeof(buf) - l, fmt, ap);
    va_end(ap);
    str_exception(no, buf);
}

static void next_ch(void) {
    if (text_pos >= text_len) return;
    text_ch = (unsigned char)text[text_pos++];
}

static int next_hex(void) {
    int ch = text_ch;
    next_ch();
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    error(ERR_INV_EXPRESSION, "Invalid hexadecimal number");
    return 0;
}

static int next_oct(void) {
    int ch = text_ch;
    next_ch();
    if (ch >= '0' && ch <= '7') return ch - '0';
    error(ERR_INV_EXPRESSION, "Invalid octal number");
    return 0;
}

static int next_dec(void) {
    int ch = text_ch;
    next_ch();
    if (ch >= '0' && ch <= '9') return ch - '0';
    error(ERR_INV_EXPRESSION, "Invalid decimal number");
    return 0;
}

static int next_char_val(void) {
    int n = 0;
    if (text_ch == '\\') {
        next_ch();
        switch (text_ch) {
        case 'n' : n = '\n'; break;
        case 't' : n = '\t'; break;
        case 'v' : n = '\v'; break;
        case 'b' : n = '\b'; break;
        case 'r' : n = '\r'; break;
        case 'f' : n = '\f'; break;
        case 'a' : n = '\a'; break;
        case '\\': n = '\\'; break;
        case '\'': n = '\''; break;
        case '"' : n = '"'; break;
        case 'x' :
            next_ch();
            n = next_hex() << 8;
            n |= next_hex() << 4;
            n |= next_hex();
            return n;
        case '0' :
        case '1' :
        case '2' :
        case '3' :
            n = next_oct() << 6;
            n |= next_oct() << 3;
            n |= next_oct();
            return n;
        default  :
            n = text_ch;
            break;
        }
    }
    else {
        n = text_ch;
    }
    next_ch();
    return n;
}

static void set_string_text_val(int pos, int len, int in_quotes) {
    int cnt = 0;
    memset(&text_val, 0, sizeof(text_val));
    text_val.type_class = TYPE_CLASS_ARRAY;
    text_val.size = len + 1;
    text_val.value = tmp_alloc((size_t)text_val.size);
    text_val.constant = 1;
    text_pos = pos - 1;
    next_ch();
    if (in_quotes) {
        while (cnt < len) {
            ((char *)text_val.value)[cnt++] = (char)next_char_val();
        }
    }
    else {
        while (cnt < len) {
            ((char *)text_val.value)[cnt++] = (char)text_ch;
            next_ch();
        }
    }
    ((char *)text_val.value)[cnt] = 0;
}

static int is_name_character(int ch) {
    if (ch >= 'A' && ch <= 'Z') return 1;
    if (ch >= 'a' && ch <= 'z') return 1;
    if (ch >= '0' && ch <= '9') return 1;
    if (ch == '_') return 1;
    if (ch == '$') return 1;
    if (ch == '@') return 1;
    return 0;
}

static void next_sy(void) {
    for (;;) {
        int ch = text_ch;
        sy_pos = text_pos - 1;
        next_ch();
        switch (ch) {
        case 0:
            text_sy = 0;
            return;
        case ' ':
        case '\r':
        case '\n':
        case '\t':
            continue;
        case '(':
        case ')':
        case '{':
        case '}':
        case '~':
        case '[':
        case ']':
        case ';':
        case '?':
        case ',':
            text_sy = ch;
            return;
        case '.':
            if (text_ch == '*') {
                next_ch();
                text_sy = SY_PM_D;
                return;
            }
            text_sy = ch;
            return;
        case ':':
            if (text_ch == ':') {
                next_ch();
                text_sy = SY_SCOPE;
                return;
            }
            text_sy = ch;
            return;
        case '-':
            if (text_ch == '>') {
                next_ch();
                if (text_ch == '*') {
                    next_ch();
                    text_sy = SY_PM_R;
                    return;
                }
                text_sy = SY_REF;
                return;
            }
            if (text_ch == '-') {
                next_ch();
                text_sy = SY_DEC;
                return;
            }
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_A_SUB;
                return;
            }
            text_sy = ch;
            return;
        case '+':
            if (text_ch == '+') {
                next_ch();
                text_sy = SY_INC;
                return;
            }
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_A_ADD;
                return;
            }
            text_sy = ch;
            return;
        case '<':
            if (text_ch == '<') {
                next_ch();
                if (text_ch == '=') {
                    next_ch();
                    text_sy = SY_A_SHL;
                    return;
                }
                text_sy = SY_SHL;
                return;
            }
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_LEQ;
                return;
            }
            text_sy = ch;
            return;
        case '>':
            if (text_ch == '>') {
                next_ch();
                if (text_ch == '=') {
                    next_ch();
                    text_sy = SY_A_SHR;
                    return;
                }
                text_sy = SY_SHR;
                return;
            }
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_GEQ;
                return;
            }
            text_sy = ch;
            return;
        case '=':
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_EQU;
                return;
            }
            text_sy = ch;
            return;
        case '!':
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_NEQ;
                return;
            }
            text_sy = ch;
            return;
        case '&':
            if (text_ch == '&') {
                next_ch();
                text_sy = SY_AND;
                return;
            }
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_A_AND;
                return;
            }
            text_sy = ch;
            return;
        case '|':
            if (text_ch == '|') {
                next_ch();
                text_sy = SY_OR;
                return;
            }
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_A_OR;
                return;
            }
            text_sy = ch;
            return;
        case '*':
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_A_MUL;
                return;
            }
            text_sy = ch;
            return;
        case '/':
            if (text_ch == '|') {
                next_ch();
                text_sy = SY_A_DIV;
                return;
            }
            text_sy = ch;
            return;
        case '%':
            if (text_ch == '|') {
                next_ch();
                text_sy = SY_A_MOD;
                return;
            }
            text_sy = ch;
            return;
        case '^':
            if (text_ch == '=') {
                next_ch();
                text_sy = SY_A_XOR;
                return;
            }
            text_sy = ch;
            return;
        case '\'':
            memset(&text_val, 0, sizeof(text_val));
            text_val.type_class = TYPE_CLASS_INTEGER;
            set_int_value(&text_val, sizeof(uint16_t), next_char_val());
            text_val.constant = 1;
            if (text_ch != '\'') error(ERR_INV_EXPRESSION, "Missing 'single quote'");
            next_ch();
            text_sy = SY_VAL;
            return;
        case '"':
            {
                int len = 0;
                int pos = text_pos;
                while (text_ch != '"') {
                    next_char_val();
                    len++;
                }
                set_string_text_val(pos, len, 1);
                text_sy = SY_VAL;
                next_ch();
            }
            return;
        case '0':
            if (text_ch == 'x') {
                uint64_t value = 0;
                next_ch();
                while ((text_ch >= '0' && text_ch <= '9') ||
                       (text_ch >= 'A' && text_ch <= 'F') ||
                       (text_ch >= 'a' && text_ch <= 'f')) {
                    value = (value << 4) | next_hex();
                }
                memset(&text_val, 0, sizeof(text_val));
                text_val.type_class = TYPE_CLASS_CARDINAL;
                set_int_value(&text_val, sizeof(uint64_t), value);
                text_val.constant = 1;
            }
            else {
                int64_t value = 0;
                while (text_ch >= '0' && text_ch <= '7') {
                    value = (value << 3) | next_oct();
                }
                memset(&text_val, 0, sizeof(text_val));
                text_val.type_class = TYPE_CLASS_INTEGER;
                set_int_value(&text_val, sizeof(int64_t), value);
                text_val.constant = 1;
            }
            text_sy = SY_VAL;
            return;
        default:
            if (ch >= '0' && ch <= '9') {
                int pos = text_pos - 2;
                int64_t value = ch - '0';
                while (text_ch >= '0' && text_ch <= '9') {
                    value = (value * 10) + next_dec();
                }
                memset(&text_val, 0, sizeof(text_val));
                if (text_ch == '.' || text_ch == 'e' || text_ch == 'E') {
                    char * end = NULL;
                    double x = strtod(text + pos, &end);
                    text_pos = end - text;
                    next_ch();
                    text_val.type_class = TYPE_CLASS_REAL;
                    if (text_ch == 'f' || text_ch == 'F') {
                        next_ch();
                        set_fp_value(&text_val, sizeof(float), x);
                    }
                    else {
                        if (text_ch == 'l' || text_ch == 'L') next_ch();
                        set_fp_value(&text_val, sizeof(double), x);
                    }
#if ENABLE_Symbols
                    find_symbol_by_name(expression_context, expression_frame,
                        expression_addr, text_val.size == sizeof(float) ? "float" : "double", &text_val.type);
                    if (text_val.type != NULL) {
                        int sym_class = 0;
                        int type_class = 0;
                        if (get_symbol_class(text_val.type, &sym_class) < 0 || sym_class != SYM_CLASS_TYPE ||
                            get_symbol_type_class(text_val.type, &type_class) < 0 || type_class != TYPE_CLASS_REAL) {
                            text_val.type = NULL;
                        }
                    }
#endif
                }
                else {
                    text_val.type_class = TYPE_CLASS_INTEGER;
                    set_int_value(&text_val, sizeof(int64_t), value);
                }
                text_val.constant = 1;
                text_sy = SY_VAL;
                return;
            }
            if (ch == '$') {
                if (text_ch == '"') {
                    int len = 0;
                    int pos = text_pos + 1;
                    next_char_val();
                    while (text_ch != '"') {
                        next_char_val();
                        len++;
                    }
                    set_string_text_val(pos, len, 1);
                    text_sy = SY_NAME;
                    next_ch();
                    return;
                }
                if (text_ch == '{') {
                    int len = 0;
                    int pos = text_pos + 1;
                    next_ch();
                    while (text_ch != '}') {
                        next_ch();
                        len++;
                    }
                    set_string_text_val(pos, len, 0);
                    text_sy = SY_ID;
                    next_ch();
                    return;
                }
            }
            if (is_name_character(ch)) {
                int len = 1;
                int pos = text_pos - 1;
                while (is_name_character(text_ch)) {
                    next_ch();
                    len++;
                }
                set_string_text_val(pos, len, 0);
                if (strcmp((const char *)text_val.value, "sizeof") == 0) text_sy = (int)SY_SIZEOF;
                else text_sy = SY_NAME;
                return;
            }
            error(ERR_INV_EXPRESSION, "Illegal character");
            break;
        }
    }
}

static void reg2value(Context * ctx, int frame, RegisterDefinition * def, Value * v) {
    if (ctx->exited) exception(ERR_ALREADY_EXITED);
    if (!ctx->stopped) str_exception(ERR_IS_RUNNING, "Cannot read CPU register");
    memset(v, 0, sizeof(Value));
    set_value(v, NULL, def->size, def->big_endian);
    v->type_class = def->fp_value ? TYPE_CLASS_REAL : TYPE_CLASS_CARDINAL;
    v->reg = def;
    if (frame == STACK_TOP_FRAME) {
        if (context_read_reg(ctx, def, 0, def->size, v->value) < 0) exception(errno);
    }
    else {
        StackFrame * info = NULL;
        if (get_frame_info(ctx, frame, &info) < 0) exception(errno);
        if (read_reg_bytes(info, def, 0, def->size, (uint8_t *)v->value) < 0) exception(errno);
    }
}

#if ENABLE_Symbols
static void set_value_endianness(Value * v, Symbol * sym, Symbol * type) {
    SYM_FLAGS flags = 0;
    if (sym != NULL && get_symbol_flags(sym, &flags) < 0) {
        error(errno, "Cannot retrieve symbol flags");
    }
    if (flags & SYM_FLAG_BIG_ENDIAN) v->big_endian = 1;
    else if (flags & SYM_FLAG_LITTLE_ENDIAN) v->big_endian = 0;
    else {
        if (type != NULL && get_symbol_flags(type, &flags) < 0) {
            error(errno, "Cannot retrieve symbol flags");
        }
        if (flags & SYM_FLAG_BIG_ENDIAN) v->big_endian = 1;
        else if (flags & SYM_FLAG_LITTLE_ENDIAN) v->big_endian = 0;
        else v->big_endian = expression_context->big_endian;
    }
}

/* Note: sym2value() does NOT set v->size if v->sym != NULL */
static int sym2value(int mode, Symbol * sym, Value * v) {
    int sym_class = 0;
    memset(v, 0, sizeof(Value));
    if (get_symbol_class(sym, &sym_class) < 0) {
        error(errno, "Cannot retrieve symbol class");
    }
    if (get_symbol_type(sym, &v->type) < 0) {
        error(errno, "Cannot retrieve symbol type");
    }
    if (get_symbol_type_class(sym, &v->type_class) < 0) {
        error(errno, "Cannot retrieve symbol type class");
    }
    switch (sym_class) {
    case SYM_CLASS_VALUE:
    case SYM_CLASS_REFERENCE:
        if (mode == MODE_NORMAL) {
            LocationExpressionState * state = NULL;
            LocationInfo * loc_info = NULL;
            StackFrame * frame_info = NULL;
            if (get_location_info(sym, &loc_info) < 0) {
                error(errno, "Cannot get symbol location information");
            }
            if (expression_frame != STACK_NO_FRAME && get_frame_info(expression_context, expression_frame, &frame_info) < 0) {
                error(errno, "Cannot get stack frame info");
            }
            state = evaluate_location_expression(expression_context, frame_info,
                loc_info->value_cmds.cmds, loc_info->value_cmds.cnt, NULL, 0);
            if (state->stk_pos == 1) {
                v->address = (ContextAddress)state->stk[0];
                v->remote = 1;
            }
            else {
                size_t size = 0;
                void * value = NULL;
                read_location_peices(expression_context, frame_info,
                    state->pieces, state->pieces_cnt, loc_info->big_endian, &value, &size);
                if (state->pieces_cnt == 1 && state->pieces->reg != NULL && state->pieces->reg->size == state->pieces->size) {
                    v->reg = state->pieces->reg;
                }
                v->size = size;
                v->value = value;
            }
            v->big_endian = loc_info->big_endian;
        }
        else {
            v->remote = 1;
        }
        v->constant = sym_class == SYM_CLASS_VALUE;
        v->sym = sym;
        break;
    case SYM_CLASS_FUNCTION:
        {
            ContextAddress word = 0;
            v->type_class = TYPE_CLASS_POINTER;
            if (v->type != NULL) get_array_symbol(v->type, 0, &v->type);
            if (mode == MODE_NORMAL && get_symbol_address(sym, &word) < 0) {
                error(errno, "Cannot retrieve symbol address");
            }
            set_ctx_word_value(v, word);
            v->function = 1;
            v->sym = sym;
        }
        break;
    default:
        v->type = sym;
        break;
    }
    return sym_class;
}

static SYM_FLAGS get_all_symbol_flags(Symbol * sym) {
    SYM_FLAGS all_flags = 0;
    for (;;) {
        Symbol * nxt = NULL;
        SYM_FLAGS sym_flags = 0;
        int sym_class = 0;
        if (get_symbol_flags(sym, &sym_flags) < 0) error(errno, "Cannot get symbol flags");
        all_flags |= sym_flags;
        if (get_symbol_class(sym, &sym_class) < 0) error(errno, "Cannot get symbol class");
        if (sym_class != SYM_CLASS_TYPE) break;
        if (get_symbol_type(sym, &nxt) < 0) error(errno, "Cannot get symbol type");
        if (nxt == sym) break;
        sym = nxt;
    }
    return all_flags;
}

static unsigned flag_count(SYM_FLAGS flags) {
    unsigned i;
    unsigned cnt = 0;
    for (i = 0; i < sizeof(flags) * 8; i++) {
        if (flags & ((SYM_FLAGS)1 << i)) cnt++;
    }
    return cnt;
}
#endif /* ENABLE_Symbols */

static int identifier(int mode, Value * scope, char * name, SYM_FLAGS flags, Value * v) {
    int i;
    memset(v, 0, sizeof(Value));
    if (scope == NULL) {
        for (i = 0; i < id_callback_cnt; i++) {
            if (id_callbacks[i](expression_context, expression_frame, name, v)) return SYM_CLASS_VALUE;
        }
        if (expression_context == NULL) {
            exception(ERR_INV_CONTEXT);
        }
        if (name[0] == '$') {
            RegisterDefinition * def = get_reg_definitions(expression_context);
            if (def != NULL) {
                while (def->name != NULL) {
                    if (strcmp(name + 1, def->name) == 0) {
                        reg2value(expression_context, expression_frame, def, v);
                        return SYM_CLASS_REFERENCE;
                    }
                    def++;
                }
            }
        }
        if (strcmp(name, "$thread") == 0) {
            set_string_value(v, expression_context->id);
            v->constant = 1;
            return SYM_CLASS_VALUE;
        }
    }
#if ENABLE_Symbols
    {
        Symbol * sym = NULL;
        int n = scope != NULL ?
            find_symbol_in_scope(expression_context, expression_frame, expression_addr, scope->type, name, &sym) :
            find_symbol_by_name(expression_context, expression_frame, expression_addr, name, &sym);

        if (n < 0) {
            if (get_error_code(errno) != ERR_SYM_NOT_FOUND) error(errno, "Cannot read symbol data");
        }
        else {
            if (flags) {
                const SYM_FLAGS flag_mask = SYM_FLAG_CONST_TYPE | SYM_FLAG_VOLATILE_TYPE |
                    SYM_FLAG_STRUCT_TYPE | SYM_FLAG_CLASS_TYPE | SYM_FLAG_UNION_TYPE | SYM_FLAG_ENUM_TYPE;
                Symbol * nxt = NULL;
                SYM_FLAGS sym_flags = (get_all_symbol_flags(sym) ^ flags) & flag_mask;
                while (find_next_symbol(&nxt) == 0) {
                    SYM_FLAGS nxt_flags = (get_all_symbol_flags(nxt) ^ flags) & flag_mask;
                    if (flag_count(nxt_flags) < flag_count(sym_flags)) sym = nxt;
                }
            }
            return sym2value(mode, sym, v);
        }
    }
#elif ENABLE_RCBP_TEST
    {
        void * ptr = NULL;
        int cls = 0;
        if (find_test_symbol(expression_context, name, &ptr, &cls) >= 0) {
            v->type_class = TYPE_CLASS_CARDINAL;
            set_ctx_word_value(v, (ContextAddress)ptr);
            return cls;
        }
    }
#endif
    return -1;
}

static int qualified_name(int mode, Value * scope, SYM_FLAGS flags, Value * v) {
    Value x;
    int sym_class = 0;
    for (;;) {
        memset(v, 0, sizeof(Value));
        if (text_sy == SY_NAME) {
            if (mode != MODE_SKIP) {
                sym_class = identifier(mode, scope, (char *)text_val.value, flags, v);
                if (sym_class < 0) error(ERR_INV_EXPRESSION, "Undefined identifier '%s'", text_val.value);
            }
            next_sy();
        }
        else if (text_sy == SY_ID) {
            if (mode != MODE_SKIP) {
                int ok = 0;
                const char * id = (char *)text_val.value;
                {
                    Context * ctx = NULL;
                    int frame = STACK_NO_FRAME;
                    RegisterDefinition * def = NULL;
                    if (id2register(id, &ctx, &frame, &def) >= 0) {
                        if (frame == STACK_TOP_FRAME) frame = expression_frame;
                        sym_class = SYM_CLASS_UNKNOWN;
                        reg2value(ctx, frame, def, v);
                        ok = 1;
                    }
                }
#if ENABLE_Symbols
                if (!ok) {
                    Symbol * sym = NULL;
                    if (id2symbol(id, &sym) >= 0) {
                        sym_class = sym2value(mode, sym, v);
                        ok = 1;
                    }
                }
#endif
                if (!ok) error(ERR_INV_EXPRESSION, "Symbol not found: %s", id);
            }
            next_sy();
        }
        else {
            error(ERR_INV_EXPRESSION, "Identifier expected");
        }
        if (text_sy != SY_SCOPE) break;
        next_sy();
        scope = &x;
        x = *v;
    }
    return sym_class;
}

static int64_t to_int(int mode, Value * v);
#define TYPE_EXPR_LENGTH 64

static int type_expression(int mode, int * buf) {
    int i = 0;
    int pos = 0;
    int expr_buf[TYPE_EXPR_LENGTH];
    int expr_len = 0;
    while (text_sy == '*') {
        next_sy();
        if (pos >= TYPE_EXPR_LENGTH) error(ERR_BUFFER_OVERFLOW, "Type expression is too long");
        buf[pos++] = 1;
    }
    if (text_sy == '(') {
        next_sy();
        expr_len = type_expression(mode, expr_buf);
        if (text_sy != ')') error(ERR_INV_EXPRESSION, "')' expected");
        next_sy();
    }
    while (text_sy == '[') {
        next_sy();
        if (text_sy != SY_VAL) error(ERR_INV_EXPRESSION, "Number expected");
        if (pos >= TYPE_EXPR_LENGTH) error(ERR_BUFFER_OVERFLOW, "Type expression is too long");
        buf[pos] = (int)to_int(mode, &text_val);
        if (mode == MODE_NORMAL && buf[pos] < 1) error(ERR_INV_EXPRESSION, "Positive number expected");
        pos++;
        next_sy();
        if (text_sy != ']') error(ERR_INV_EXPRESSION, "']' expected");
        next_sy();
    }
    for (i = 0; i < expr_len; i++) {
        if (pos >= TYPE_EXPR_LENGTH) error(ERR_BUFFER_OVERFLOW, "Type expression is too long");
        buf[pos++] = expr_buf[i];
    }
    return pos;
}

static int type_name(int mode, Symbol ** type) {
    Value v;
    int expr_buf[TYPE_EXPR_LENGTH];
    int expr_len = 0;
    char * name = NULL;
    int sym_class;
    SYM_FLAGS sym_flags = 0;
    int name_cnt = 0;

    while (text_sy == SY_NAME) {
        if (strcmp((const char *)(text_val.value), "const") == 0) {
            sym_flags |= SYM_FLAG_CONST_TYPE;
            next_sy();
        }
        else if (strcmp((const char *)(text_val.value), "volatile") == 0) {
            sym_flags |= SYM_FLAG_VOLATILE_TYPE;
            next_sy();
        }
        else {
            break;
        }
    }
    if (text_sy == SY_NAME) {
        if (strcmp((const char *)(text_val.value), "struct") == 0) {
            sym_flags |= SYM_FLAG_STRUCT_TYPE;
            next_sy();
        }
        else if (strcmp((const char *)(text_val.value), "class") == 0) {
            sym_flags |= SYM_FLAG_CLASS_TYPE;
            next_sy();
        }
        else if (strcmp((const char *)(text_val.value), "union") == 0) {
            sym_flags |= SYM_FLAG_UNION_TYPE;
            next_sy();
        }
        else if (strcmp((const char *)(text_val.value), "enum") == 0) {
            sym_flags |= SYM_FLAG_ENUM_TYPE;
            next_sy();
        }
    }

    if (text_sy == SY_NAME) {
        do {
            if (name == NULL) {
                name = tmp_strdup((char *)text_val.value);
            }
            else {
                name = tmp_strdup2(name, " ");
                name = tmp_strdup2(name, (char *)text_val.value);
            }
            name_cnt++;
            next_sy();
        }
        while (text_sy == SY_NAME);
        if (text_sy == '<') {
            int prev_sy = 0;
            unsigned cnt = 0;
            uint64_t val = 0;
            char tmp_buf[40];
            do {
                switch (text_sy) {
                case SY_NAME:
                    if (prev_sy == SY_NAME || prev_sy == '*' || prev_sy == '&')
                        name = tmp_strdup2(name, " ");
                    name = tmp_strdup2(name, (char *)text_val.value);
                    break;
                case SY_SCOPE:
                    name = tmp_strdup2(name, "::");
                    break;
                case SY_VAL:
                    value_to_unsigned(&text_val, &val);
                    snprintf(tmp_buf, sizeof(tmp_buf), "%lu", (unsigned long)val);
                    name = tmp_strdup2(name, tmp_buf);
                    break;
                case '*':
                case '&':
                case '[':
                case ']':
                case '(':
                case ')':
                case '{':
                case '}':
                    tmp_buf[0] = (char)text_sy;
                    tmp_buf[1] = 0;
                    name = tmp_strdup2(name, tmp_buf);
                    break;
                case ',':
                    name = tmp_strdup2(name, ", ");
                    break;
                case '<':
                    name = tmp_strdup2(name, "<");
                    cnt++;
                    break;
                case '>':
                    if (prev_sy == '>') name = tmp_strdup2(name, " ");
                    name = tmp_strdup2(name, ">");
                    cnt--;
                    break;
                default:
                    return 0;
                }
                prev_sy = text_sy;
                next_sy();
            }
            while (cnt > 0);
        }
        sym_class = identifier(mode, NULL, name, sym_flags, &v);
    }
#if ENABLE_Symbols
    else if (text_sy == SY_ID) {
        Symbol * sym = NULL;
        const char * id = (const char *)text_val.value;
        if (id2symbol(id, &sym) < 0) return 0;
        sym_class = sym2value(mode, sym, &v);
        name = tmp_strdup(id);
        next_sy();
    }
#endif
    else {
        if (sym_flags) error(ERR_INV_EXPRESSION, "Identifier expected");
        return 0;
    }

    if (sym_class < 0) return 0;
    if (text_sy == SY_SCOPE) {
        Value scope = v;
        next_sy();
        sym_class = qualified_name(mode, &scope, sym_flags, &v);
    }
    if (sym_class != SYM_CLASS_TYPE) {
        if (sym_flags) error(ERR_INV_EXPRESSION, "Type '%s' not found", name);
        return 0;
    }
    expr_len = type_expression(mode, expr_buf);
    if (mode != MODE_SKIP) {
        int i;
        for (i = 0; i < expr_len; i++) {
#if ENABLE_Symbols
            if (expr_buf[i] == 1) {
                if (get_array_symbol(v.type, 0, &v.type)) {
                    error(errno, "Cannot create pointer type");
                }
            }
            else {
                if (get_array_symbol(v.type, expr_buf[i], &v.type)) {
                    error(errno, "Cannot create array type");
                }
            }
#else
            v.type = NULL;
#endif
        }
    }
    *type = v.type;
    return 1;
}

static void load_value(Value * v) {
    v->sym = NULL;
    v->reg = NULL;
    if (v->remote) {
        size_t size = (size_t)v->size;
        void * buf = tmp_alloc(size);
        assert(!v->constant);
        if (context_read_mem(expression_context, v->address, buf, size) < 0) {
            error(errno, "Can't read variable value");
        }
        v->value = buf;
        v->remote = 0;
    }
}

static int is_number(Value * v) {
    switch (v->type_class) {
    case TYPE_CLASS_INTEGER:
    case TYPE_CLASS_CARDINAL:
    case TYPE_CLASS_REAL:
    case TYPE_CLASS_ENUMERATION:
        return 1;
    }
    return 0;
}

static int is_whole_number(Value * v) {
    switch (v->type_class) {
    case TYPE_CLASS_INTEGER:
    case TYPE_CLASS_CARDINAL:
    case TYPE_CLASS_ENUMERATION:
        return 1;
    }
    return 0;
}

static void to_host_endianness(Value * v) {
    assert(v->type_class != TYPE_CLASS_COMPOSITE);
    assert(v->type_class != TYPE_CLASS_ARRAY);
    assert(!v->remote);
    if (v->big_endian != big_endian) {
        size_t i = 0;
        size_t n = (size_t)v->size;
        uint8_t * buf = (uint8_t *)tmp_alloc(n);
        for (i = 0; i < n; i++) {
            buf[i] = ((uint8_t *)v->value)[n - i - 1];
        }
        v->value = buf;
        v->big_endian = big_endian;
        v->sym = NULL;
        v->reg = NULL;
    }
}

static int64_t to_int(int mode, Value * v) {
    if (mode != MODE_NORMAL) {
        v->sym = NULL;
        v->reg = NULL;
        if (v->remote) {
            v->value = tmp_alloc_zero((size_t)v->size);
            v->remote = 0;
        }
        return 0;
    }

    if (v->type_class == TYPE_CLASS_POINTER) {
        load_value(v);
        to_host_endianness(v);
        switch (v->size)  {
        case 1: return *(uint8_t *)v->value;
        case 2: return *(uint16_t *)v->value;
        case 4: return *(uint32_t *)v->value;
        case 8: return *(uint64_t *)v->value;
        }
    }
    if (is_number(v)) {
        load_value(v);
        to_host_endianness(v);

        if (v->type_class == TYPE_CLASS_REAL) {
            switch (v->size)  {
            case 4: return (int64_t)*(float *)v->value;
            case 8: return (int64_t)*(double *)v->value;
            }
        }
        else if (v->type_class == TYPE_CLASS_CARDINAL) {
            switch (v->size)  {
            case 1: return (int64_t)*(uint8_t *)v->value;
            case 2: return (int64_t)*(uint16_t *)v->value;
            case 4: return (int64_t)*(uint32_t *)v->value;
            case 8: return (int64_t)*(uint64_t *)v->value;
            }
        }
        else {
            switch (v->size)  {
            case 1: return *(int8_t *)v->value;
            case 2: return *(int16_t *)v->value;
            case 4: return *(int32_t *)v->value;
            case 8: return *(int64_t *)v->value;
            }
        }
    }

    error(ERR_INV_EXPRESSION, "Operation is not applicable for the value type");
    return 0;
}

static uint64_t to_uns(int mode, Value * v) {
    if (mode != MODE_NORMAL) {
        v->sym = NULL;
        v->reg = NULL;
        if (v->remote) {
            v->value = tmp_alloc_zero((size_t)v->size);
            v->remote = 0;
        }
        return 0;
    }

    if (v->type_class == TYPE_CLASS_ARRAY && v->remote) {
        return (uint64_t)v->address;
    }
    if (v->type_class == TYPE_CLASS_POINTER) {
        load_value(v);
        to_host_endianness(v);
        switch (v->size)  {
        case 1: return *(uint8_t *)v->value;
        case 2: return *(uint16_t *)v->value;
        case 4: return *(uint32_t *)v->value;
        case 8: return *(uint64_t *)v->value;
        }
    }
    if (is_number(v)) {
        load_value(v);
        to_host_endianness(v);

        if (v->type_class == TYPE_CLASS_REAL) {
            switch (v->size)  {
            case 4: return (uint64_t)*(float *)v->value;
            case 8: return (uint64_t)*(double *)v->value;
            }
        }
        else if (v->type_class == TYPE_CLASS_CARDINAL) {
            switch (v->size)  {
            case 1: return *(uint8_t *)v->value;
            case 2: return *(uint16_t *)v->value;
            case 4: return *(uint32_t *)v->value;
            case 8: return *(uint64_t *)v->value;
            }
        }
        else {
            switch (v->size)  {
            case 1: return (uint64_t)*(int8_t *)v->value;
            case 2: return (uint64_t)*(int16_t *)v->value;
            case 4: return (uint64_t)*(int32_t *)v->value;
            case 8: return (uint64_t)*(int64_t *)v->value;
            }
        }
    }

    error(ERR_INV_EXPRESSION, "Operation is not applicable for the value type");
    return 0;
}

static double to_double(int mode, Value * v) {
    if (mode != MODE_NORMAL) {
        v->sym = NULL;
        v->reg = NULL;
        if (v->remote) {
            v->value = tmp_alloc_zero((size_t)v->size);
            v->remote = 0;
        }
        return 0;
    }

    if (is_number(v)) {
        load_value(v);
        to_host_endianness(v);

        if (v->type_class == TYPE_CLASS_REAL) {
            switch (v->size)  {
            case 4: return *(float *)v->value;
            case 8: return *(double *)v->value;
            }
        }
        else if (v->type_class == TYPE_CLASS_CARDINAL) {
            switch (v->size)  {
            case 1: return (double)*(uint8_t *)v->value;
            case 2: return (double)*(uint16_t *)v->value;
            case 4: return (double)*(uint32_t *)v->value;
            case 8: return (double)*(uint64_t *)v->value;
            }
        }
        else {
            switch (v->size)  {
            case 1: return (double)*(int8_t *)v->value;
            case 2: return (double)*(int16_t *)v->value;
            case 4: return (double)*(int32_t *)v->value;
            case 8: return (double)*(int64_t *)v->value;
            }
        }
    }

    error(ERR_INV_EXPRESSION, "Operation is not applicable for the value type");
    return 0;
}

static int to_boolean(int mode, Value * v) {
    return to_int(mode, v) != 0;
}

static void expression(int mode, Value * v);

static void qualified_name_expression(int mode, Value * scope, Value * v) {
    if (qualified_name(mode, scope, 0, v) != SYM_CLASS_TYPE) return;
    error(ERR_INV_EXPRESSION, "Illegal usage of a type in expression");
}

static void primary_expression(int mode, Value * v) {
    if (text_sy == '(') {
        next_sy();
        expression(mode, v);
        if (text_sy != ')') error(ERR_INV_EXPRESSION, "Missing ')'");
        next_sy();
    }
    else if (text_sy == SY_VAL) {
        *v = text_val;
        next_sy();
        if (v->type_class == TYPE_CLASS_ARRAY && text_sy == SY_SCOPE) {
            Value x;
            char * name = (char *)v->value;
            if (identifier(mode, NULL, name, 0, &x) < 0)
                error(ERR_INV_EXPRESSION, "Undefined identifier '%s'", name);
            next_sy();
            qualified_name_expression(mode, &x, v);
        }
    }
    else if (text_sy == SY_SCOPE) {
        Value x;
        next_sy();
        memset(&x, 0, sizeof(x));
        qualified_name_expression(mode, &x, v);
    }
    else if (text_sy == SY_NAME || text_sy == SY_ID) {
        qualified_name_expression(mode, NULL, v);
    }
    else {
        error(ERR_INV_EXPRESSION, "Syntax error");
    }
}

static void op_deref(int mode, Value * v) {
#if ENABLE_Symbols
    Symbol * type = NULL;
    if (mode == MODE_SKIP) return;
    if (v->type_class != TYPE_CLASS_ARRAY && v->type_class != TYPE_CLASS_POINTER) {
        error(ERR_INV_EXPRESSION, "Array or pointer type expected");
    }
    if (get_symbol_base_type(v->type, &type) < 0) {
        error(errno, "Cannot retrieve symbol type");
    }
    if (v->type_class == TYPE_CLASS_POINTER) {
        if (v->sym != NULL && v->size == 0 && get_symbol_size(v->sym, &v->size) < 0) {
            error(errno, "Cannot retrieve symbol size");
        }
        v->address = (ContextAddress)to_uns(mode, v);
        v->remote = 1;
        v->constant = 0;
        v->value = NULL;
        set_value_endianness(v, NULL, type);
    }
    v->type = type;
    if (get_symbol_type_class(v->type, &v->type_class) < 0) {
        error(errno, "Cannot retrieve symbol type class");
    }
    if (get_symbol_size(v->type, &v->size) < 0) {
        error(errno, "Cannot retrieve symbol size");
    }
#else
    error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
}

#if ENABLE_Symbols
static void evaluate_symbol_address(Symbol * sym, ContextAddress obj_addr, ContextAddress index, ContextAddress * addr) {
    ContextAddress offs = 0;
    if (get_symbol_offset(sym, &offs) == 0) {
        *addr = obj_addr + offs;
    }
    else {
        LocationExpressionState * state = NULL;
        LocationInfo * loc_info = NULL;
        StackFrame * frame_info = NULL;
        uint64_t args[2];
        args[0] = obj_addr;
        args[1] = index;
        if (get_location_info(sym, &loc_info) < 0) {
            error(errno, "Cannot get symbol location information");
        }
        if (expression_frame != STACK_NO_FRAME && get_frame_info(expression_context, expression_frame, &frame_info) < 0) {
            error(errno, "Cannot get stack frame info");
        }
        state = evaluate_location_expression(expression_context, frame_info,
            loc_info->value_cmds.cmds, loc_info->value_cmds.cnt, args, 2);
        if (state->stk_pos != 1) error(ERR_INV_EXPRESSION, "Cannot evaluate symbol address");
        *addr = (ContextAddress)state->stk[0];
    }
}

static void find_field(Symbol * class_sym, ContextAddress obj_addr, const char * name, const char * id, Symbol ** field_sym, ContextAddress * field_addr) {
    Symbol ** children = NULL;
    Symbol ** inheritance = NULL;
    int count = 0;
    int h = 0;
    int i;

    if (get_symbol_children(class_sym, &children, &count) < 0) {
        error(errno, "Cannot retrieve field list");
    }
    for (i = 0; i < count; i++) {
        char * s = NULL;
        if (get_symbol_name(children[i], &s) < 0) {
            error(errno, "Cannot retrieve field name");
        }
        if (s == NULL) {
            if (inheritance == NULL) inheritance = (Symbol **)tmp_alloc(sizeof(Symbol *) * count);
            inheritance[h++] = children[i];
        }
        if ((name != NULL && s != NULL && strcmp(s, name) == 0) ||
                (id != NULL && strcmp(symbol2id(children[i]), id) == 0)) {
            evaluate_symbol_address(children[i], obj_addr, 0, field_addr);
            *field_sym = children[i];
            return;
        }
    }
    for (i = 0; i < h; i++) {
        ContextAddress x = 0;
        evaluate_symbol_address(inheritance[i], obj_addr, 0, &x);
        find_field(inheritance[i], x, name, id, field_sym, field_addr);
        if (*field_sym != NULL) return;
    }
}
#endif

static void op_field(int mode, Value * v) {
    char * id = NULL;
    char * name = NULL;
    if (text_sy == SY_ID) id = (char *)text_val.value;
    else if (text_sy == SY_NAME) name = (char *)text_val.value;
    else error(ERR_INV_EXPRESSION, "Field name expected");
    next_sy();
    if (mode == MODE_SKIP) return;
    if (v->type_class == TYPE_CLASS_COMPOSITE) {
#if ENABLE_Symbols
        Symbol * sym = NULL;
        int sym_class = 0;
        ContextAddress addr = 0;

        if (!v->remote) error(ERR_INV_EXPRESSION, "L-value expected");
        find_field(v->type, v->address, name, id, &sym, &addr);
        if (sym == NULL) {
            error(ERR_SYM_NOT_FOUND, "Invalid field name or ID");
        }
        if (get_symbol_class(sym, &sym_class) < 0) {
            error(errno, "Cannot retrieve symbol class");
        }
        if (sym_class == SYM_CLASS_FUNCTION) {
            get_symbol_type(sym, &v->type);
            v->type_class = TYPE_CLASS_POINTER;
            if (v->type != NULL) get_array_symbol(v->type, 0, &v->type);
            set_ctx_word_value(v, addr);
            v->function = 1;
            v->sym = sym;
        }
        else {
            ContextAddress size = 0;
            if (get_symbol_size(sym, &size) < 0) {
                error(errno, "Cannot retrieve field size");
            }
            v->address = addr;
            v->size = size;
            v->sym = NULL;
            v->reg = NULL;
            if (get_symbol_type(sym, &v->type) < 0) {
                error(errno, "Cannot retrieve symbol type");
            }
            if (get_symbol_type_class(sym, &v->type_class) < 0) {
                error(errno, "Cannot retrieve symbol type class");
            }
            set_value_endianness(v, sym, v->type);
        }
#else
        error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
    }
    else if (v->reg != NULL) {
        if (id != NULL) {
            Context * ctx = NULL;
            int frame = STACK_NO_FRAME;
            RegisterDefinition * def = NULL;
            if (id2register(id, &ctx, &frame, &def) < 0) exception(errno);
            if (frame == STACK_TOP_FRAME) frame = expression_frame;
            reg2value(ctx, frame, def, v);
        }
        else {
            RegisterDefinition * def = get_reg_definitions(expression_context);
            if (def != NULL) {
                while (def->name != NULL) {
                    if (def->parent == v->reg && strcmp(name, def->name) == 0) {
                        reg2value(expression_context, expression_frame, def, v);
                        return;
                    }
                    def++;
                }
            }
            error(ERR_INV_EXPRESSION, "Unknown register; %s", name);
        }
    }
    else {
        error(ERR_INV_EXPRESSION, "Composite type expected");
    }
}

static void op_index(int mode, Value * v) {
#if ENABLE_Symbols
    Value i;
    int64_t lower_bound = 0;
    ContextAddress offs = 0;
    ContextAddress size = 0;
    Symbol * type = NULL;

    expression(mode, &i);
    if (mode == MODE_SKIP) return;

    if (v->type_class != TYPE_CLASS_ARRAY && v->type_class != TYPE_CLASS_POINTER) {
        error(ERR_INV_EXPRESSION, "Array or pointer expected");
    }
    if (v->type == NULL) {
        error(ERR_INV_EXPRESSION, "Value type is unknown");
    }
    if (get_symbol_base_type(v->type, &type) < 0) {
        error(errno, "Cannot get array element type");
    }
    if (v->type_class == TYPE_CLASS_POINTER) {
        v->address = (ContextAddress)to_uns(mode, v);
        v->remote = 1;
        v->constant = 0;
        v->value = NULL;
        set_value_endianness(v, NULL, type);
    }
    if (get_symbol_size(type, &size) < 0) {
        error(errno, "Cannot get array element size");
    }
    if (v->type_class == TYPE_CLASS_ARRAY && get_symbol_lower_bound(v->type, &lower_bound) < 0) {
        error(errno, "Cannot get array lower bound");
    }
    offs = (ContextAddress)(to_int(mode, &i) - lower_bound) * size;
    if (v->sym != NULL && v->size == 0 && get_symbol_size(v->sym, &v->size) < 0) {
        error(errno, "Cannot retrieve symbol size");
    }
    if (v->type_class == TYPE_CLASS_ARRAY && offs + size > v->size) {
        error(ERR_INV_EXPRESSION, "Invalid index");
    }
    if (v->remote) {
        v->address += offs;
    }
    else {
        v->value = (char *)v->value + offs;
    }
    v->sym = NULL;
    v->reg = NULL;
    v->size = size;
    v->type = type;
    if (get_symbol_type_class(type, &v->type_class) < 0) {
        error(errno, "Cannot retrieve symbol type class");
    }
#else
    error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
}

static void op_addr(int mode, Value * v) {
    if (mode == MODE_SKIP) return;
    if (v->function) {
        assert(v->type_class == TYPE_CLASS_POINTER);
    }
    else {
        if (!v->remote) error(ERR_INV_EXPRESSION, "Invalid '&': value has no address");
        set_ctx_word_value(v, v->address);
        v->type_class = TYPE_CLASS_POINTER;
        v->constant = 0;
#if ENABLE_Symbols
        if (v->type != NULL) {
            if (get_array_symbol(v->type, 0, &v->type)) {
                error(errno, "Cannot get pointer type");
            }
        }
#else
        v->type = NULL;
#endif
    }
}

static void unary_expression(int mode, Value * v);

static void op_sizeof(int mode, Value * v) {
    Symbol * type = NULL;
    int pos = 0;
    int p = text_sy == '(';

    if (p) next_sy();
    pos = sy_pos;
    if (type_name(mode, &type)) {
        if (mode != MODE_SKIP) {
            ContextAddress type_size = 0;
#if ENABLE_Symbols
            if (get_symbol_size(type, &type_size) < 0) {
                error(errno, "Cannot retrieve symbol size");
            }
#endif
            set_ctx_word_value(v, type_size);
            v->type = NULL;
            v->type_class = TYPE_CLASS_CARDINAL;
            v->constant = 1;
        }
    }
    else {
        text_pos = pos;
        next_ch();
        next_sy();
        unary_expression(mode == MODE_NORMAL ? MODE_TYPE : mode, v);
        if (mode != MODE_SKIP) {
            set_ctx_word_value(v, v->size);
            v->type = NULL;
            v->type_class = TYPE_CLASS_CARDINAL;
            v->constant = 1;
        }
    }
    if (p) {
        if (text_sy != ')') error(ERR_INV_EXPRESSION, "')' expected");
        next_sy();
    }
}

static void funccall_error(const char * msg) {
    set_errno(ERR_OTHER, msg);
    set_errno(errno, "Cannot inject a function call");
    exception(errno);
}

#if ENABLE_FuncCallInjection

static void free_funccall_state(FuncCallState * state) {
    assert(!state->started || state->intercepted);
    assert(state->committed);
    assert(state->regs_cnt == 0 || state->error);
    list_remove(&state->link_all);
    if (state->bp) destroy_eventpoint(state->bp);
    context_unlock(state->ctx);
    release_error_report(state->error);
    loc_free(state->ret_value);
    loc_free(state->args);
    loc_free(state->cmds);
    loc_free(state->regs);
    loc_free(state);
}

static void funcccall_breakpoint(Context * ctx, void * args) {
    Trap trap;
    FuncCallState * state = (FuncCallState *)args;
    assert(state->ctx == ctx);
    assert(state->started);
    assert(!state->finished);
    ctx->stopped_by_funccall = 1;
    if (set_trap(&trap)) {
        if (!state->intercepted && state->cmds_cnt > 0) {
            /* Execute after call commands */
            StackFrame * frame_info = NULL;
            LocationExpressionState * vm = NULL;
            if (get_frame_info(ctx, STACK_TOP_FRAME, &frame_info) < 0) exception(errno);
            vm = evaluate_location_expression(ctx, frame_info,
                    state->cmds, state->cmds_cnt, NULL, 0);
            state->cmds_cnt = 0;

            /* Read function call returned value */
            if (vm->pieces_cnt > 0) {
                void * value = NULL;
                read_location_peices(ctx, frame_info, vm->pieces, vm->pieces_cnt,
                        state->ret_big_endian, &value, &state->ret_size);
                state->ret_value = loc_alloc_zero(state->ret_size);
                memcpy(state->ret_value, value, state->ret_size);
            }
            else if (vm->stk_pos > 0) {
                state->ret_size = sizeof(uint64_t);
                state->ret_value = loc_alloc_zero(state->ret_size);
                memcpy(state->ret_value, vm->stk + vm->stk_pos - 1, state->ret_size);
            }
        }
        if (state->regs_cnt > 0) {
            /* Restore registers */
            unsigned i;
            unsigned offs = 0;
            for (i = 0; i < state->regs_cnt; i++) {
                RegisterDefinition * r = state->regs[i];
                if (context_write_reg(ctx, r, 0, r->size, state->regs_data + offs) < 0) exception(errno);
                send_event_register_changed(register2id(ctx, STACK_TOP_FRAME, r));
                offs += r->size;
            }
            state->regs_cnt = 0;
        }
        clear_trap(&trap);
    }
    else {
        release_error_report(state->error);
        state->error = get_error_report(trap.error);
    }
    if (!state->intercepted) {
        assert(!state->finished);
        state->finished = 1;
        suspend_debug_context(ctx);
    }
    else if (state->committed) {
        if (state->error) trace(LOG_ALWAYS, "Cannot restore state",
            errno_to_str(set_error_report_errno(state->error)));
        free_funccall_state(state);
    }
}

static void funccall_check_recursion(uint64_t ret_addr) {
    LINK * l = func_call_state.next;
    while (l != &func_call_state) {
        FuncCallState * state = link_all2fc(l);
        if (state->started && !state->finished &&
                state->ctx == expression_context && state->ret_addr == ret_addr) {
            funccall_error("Recursive invocation");
        }
        l = l->next;
    }
}

static void op_call(int mode, Value * v) {
    unsigned id = cache_transaction_id();
    FuncCallState * state = NULL;
    Symbol * func = NULL;
    int type_class = 0;
    LINK * l;

    if (!context_has_state(expression_context)) funccall_error("Context is not a thread");
    if (is_safe_event()) funccall_error("Called from safe event handler");

    for (l = func_call_state.next; l != &func_call_state; l = l->next) {
        FuncCallState * s = link_all2fc(l);
        if (s->id == id || s->pos == text_pos) {
            state = s;
            break;
        }
    }

    if (state != NULL && state->started && !state->intercepted) cache_wait(&state->cache);
    if (state == NULL) {
        state = (FuncCallState *)loc_alloc_zero(sizeof(FuncCallState));
        state->id = id;
        state->pos = text_pos;
        context_lock(state->ctx = expression_context);
        list_add_first(&state->link_all, &func_call_state);
    }
    if (v->function) {
        func = v->sym;
    }
    else if (v->type != NULL && v->type_class == TYPE_CLASS_POINTER) {
        if (get_symbol_base_type(v->type, &func) < 0) {
            error(errno, "Cannot retrieve symbol base type");
        }
    }
    if (func != NULL && get_symbol_type_class(func, &type_class) < 0) {
        error(errno, "Cannot retrieve symbol type class");
    }
    if (type_class != TYPE_CLASS_FUNCTION) {
        error(ERR_INV_EXPRESSION, "Invalid '()': not a function");
    }
    if (get_symbol_address(func, &state->func_addr) < 0) {
        error(errno, "Cannot retrieve function address");
    }
    state->args_cnt = 0;
    if (state->args_max) memset(state->args, 0, sizeof(Value) * state->args_max);
    if (text_sy != ')') {
        int args_mode = mode;
        if (state->started) args_mode = MODE_SKIP;
        for (;;) {
            if (state->args_cnt >= state->args_max) {
                state->args_max += 8;
                state->args = (Value *)loc_realloc(state->args, sizeof(Value) * state->args_max);
            }
            expression(args_mode, state->args + state->args_cnt++);
            if (text_sy != ',') break;
            next_sy();
        }
    }
    if (get_symbol_base_type(func, &v->type) < 0) {
        error(errno, "Cannot retrieve function return type");
    }
    if (get_symbol_type_class(v->type, &v->type_class) < 0) {
        error(errno, "Cannot retrieve function return type class");
    }
    if (get_symbol_size(v->type, &v->size) < 0) {
        error(errno, "Cannot retrieve function return value size");
    }
    expression_has_func_call = 1;
    if (mode == MODE_NORMAL) {
        if (!state->started) {
            unsigned i;
            StackFrame * frame_info = NULL;
            FunctionCallInfo * call_info = NULL;
            LocationExpressionState * vm = NULL;
            RegisterDefinition * reg_pc = get_PC_definition(state->ctx);
            const Symbol ** arg_types = (const Symbol **)tmp_alloc_zero(sizeof(Symbol *) * state->args_cnt);
            uint64_t * arg_vals = (uint64_t *)tmp_alloc_zero(sizeof(uint64_t) * (FUNCCALL_ARG_ARGS + state->args_cnt));
            uint64_t sp = 0;

            if (get_frame_info(state->ctx, STACK_TOP_FRAME, &frame_info) < 0) exception(errno);
            if (read_reg_value(frame_info, reg_pc, &state->ret_addr) < 0) exception(errno);
            funccall_check_recursion(state->ret_addr);
            for (i = 0; i < state->args_cnt; i++) arg_types[i] = state->args[i].type;
            if (get_funccall_info(func, arg_types, state->args_cnt, &call_info) < 0) exception(errno);

            /* Save registers */
            if (call_info->saveregs_cnt > 0) {
                unsigned offs = 0;
                for (i = 0; i < call_info->saveregs_cnt; i++) offs += call_info->saveregs[i]->size;
                state->regs = (RegisterDefinition **)loc_alloc(sizeof(RegisterDefinition *) * call_info->saveregs_cnt);
                state->regs_data = (uint8_t *)loc_alloc_zero(offs);
                state->regs_cnt = call_info->saveregs_cnt;
                offs = 0;
                for (i = 0; i < call_info->saveregs_cnt; i++) {
                    RegisterDefinition * r = call_info->saveregs[i];
                    state->regs[i] = r;
                    if (context_read_reg(state->ctx, r, 0, r->size, state->regs_data + offs) < 0) exception(errno);
                    offs += r->size;
                }
            }

            /* get values of actual arguments */
            arg_vals[FUNCCALL_ARG_ADDR] = state->func_addr;
            arg_vals[FUNCCALL_ARG_RET] = state->ret_addr;
            if (read_reg_value(frame_info, call_info->stak_pointer, &sp) < 0) exception(errno);
            sp -= call_info->red_zone_size;
            for (i = 0; i < state->args_cnt; i++) {
                Value * v = state->args + i;
                switch (v->type_class) {
                case TYPE_CLASS_CARDINAL:
                case TYPE_CLASS_INTEGER:
                case TYPE_CLASS_POINTER:
                case TYPE_CLASS_ENUMERATION:
                    arg_vals[FUNCCALL_ARG_ARGS + i] = to_uns(MODE_NORMAL, v);
                    break;
                default:
                    if (v->remote) {
                        arg_vals[FUNCCALL_ARG_ARGS + i] = v->address;
                    }
                    else {
                        sp -= v->size;
                        while (sp % 8) sp--;
                        if (context_write_mem(state->ctx, (ContextAddress)sp,
                                v->value, (size_t)v->size) < 0) exception(errno);
                        arg_vals[FUNCCALL_ARG_ARGS + i] = sp;
                    }
                    break;
                }
            }
            if (write_reg_value(frame_info, call_info->stak_pointer, sp) < 0) exception(errno);

            /* Execute call injection commands */
            state->started = 1;
            vm = evaluate_location_expression(state->ctx, frame_info,
                    call_info->cmds, call_info->cmds_cnt, arg_vals, FUNCCALL_ARG_ARGS + state->args_cnt);
            state->ret_big_endian = call_info->scope.big_endian;
            if (vm->sft_cmd != NULL) {
                char ret_addr[64];
                if (vm->sft_cmd->cmd != SFT_CMD_FCALL || vm->stk_pos != 0) {
                    funccall_error("Invalid SFT instruction");
                }

                /* Create breakpoint at the function return address */
                assert(state->bp == NULL);
                snprintf(ret_addr, sizeof(ret_addr), "0x%" PRIX64, state->ret_addr);
                state->bp = create_eventpoint(ret_addr, state->ctx, funcccall_breakpoint, state);

                /* Set PC to the function address */
                if (write_reg_value(frame_info, reg_pc, state->func_addr) < 0) exception(errno);
                state->ctx->stopped_by_bp = 0;

                /* Save rest of func call commands to be executed after the function returns */
                state->cmds_cnt = call_info->cmds_cnt - (vm->sft_cmd - call_info->cmds) - 1;
                state->cmds = (LocationExpressionCommand *)loc_alloc(sizeof(LocationExpressionCommand) * state->cmds_cnt);
                memcpy(state->cmds, vm->sft_cmd + 1, sizeof(LocationExpressionCommand) * state->cmds_cnt);

                /* Resume debug context */
                if (continue_debug_context(state->ctx, cache_channel(), RM_RESUME, 1, 0, 0) < 0) exception(errno);

                /* Wait until the function returns */
                cache_wait(&state->cache);
            }
            else {
                state->finished = 1;
            }
        }
        assert(state->started);
        assert(state->intercepted);
        if (state->error) exception(set_error_report_errno(state->error));
        set_value(v, state->ret_value, state->ret_size, state->ret_big_endian);
    }
    else {
        set_value(v, NULL, (size_t)v->size, 0);
    }
}

#else

static void op_call(int mode, Value * v) {
    funccall_error("Symbols service not available");
}

#endif /* ENABLE_FuncCallInjection */

static void postfix_expression(int mode, Value * v) {
    primary_expression(mode, v);
    for (;;) {
        if (text_sy == '.') {
            next_sy();
            op_field(mode, v);
        }
        else if (text_sy == '[') {
            next_sy();
            op_index(mode, v);
            if (text_sy != ']') {
                error(ERR_INV_EXPRESSION, "']' expected");
            }
            next_sy();
        }
        else if (text_sy == SY_REF) {
            next_sy();
            op_deref(mode, v);
            op_field(mode, v);
        }
        else if (text_sy == '(') {
            next_sy();
            op_call(mode, v);
            if (text_sy != ')') {
                error(ERR_INV_EXPRESSION, "')' expected");
            }
            next_sy();
        }
        else {
            break;
        }
    }
}

/* Note: lazy_unary_expression() does not set v->size if v->sym != NULL */
static void lazy_unary_expression(int mode, Value * v) {
    switch (text_sy) {
    case '*':
        next_sy();
        lazy_unary_expression(mode, v);
        op_deref(mode, v);
        break;
    case '&':
        next_sy();
        lazy_unary_expression(mode, v);
        op_addr(mode, v);
        break;
    case SY_SIZEOF:
        next_sy();
        op_sizeof(mode, v);
        break;
    case '+':
        next_sy();
        lazy_unary_expression(mode, v);
        break;
    case '-':
        next_sy();
        unary_expression(mode, v);
        if (mode != MODE_SKIP) {
            if (!is_number(v)) {
                error(ERR_INV_EXPRESSION, "Numeric types expected");
            }
            else if (v->type_class == TYPE_CLASS_REAL) {
                set_fp_value(v, sizeof(double), -to_double(mode, v));
            }
            else if (v->type_class != TYPE_CLASS_CARDINAL) {
                int64_t value = -to_int(mode, v);
                v->type_class = TYPE_CLASS_INTEGER;
                set_int_value(v, sizeof(int64_t), value);
            }
            assert(!v->remote);
            v->type = NULL;
        }
        break;
    case '!':
        next_sy();
        unary_expression(mode, v);
        if (mode != MODE_SKIP) {
            if (!is_whole_number(v)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            else {
                int32_t value = !to_int(mode, v);
                v->type_class = TYPE_CLASS_INTEGER;
                set_int_value(v, sizeof(int32_t), value);
            }
            assert(!v->remote);
            v->type = NULL;
        }
        break;
    case '~':
        next_sy();
        unary_expression(mode, v);
        if (mode != MODE_SKIP) {
            if (!is_whole_number(v)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            else {
                int64_t value = ~to_int(mode, v);
                set_int_value(v, sizeof(int64_t), value);
            }
            assert(!v->remote);
            v->type = NULL;
        }
        break;
#if ENABLE_Symbols
    case '(':
    {
        Symbol * type = NULL;
        int type_class = TYPE_CLASS_UNKNOWN;
        ContextAddress type_size = 0;
        int pos = sy_pos;

        assert(text[pos] == '(');
        next_sy();
        if (!type_name(mode, &type)) {
            text_pos = pos;
            next_ch();
            next_sy();
            assert(text_sy == '(');
            postfix_expression(mode, v);
            break;
        }
        if (text_sy != ')') error(ERR_INV_EXPRESSION, "')' expected");
        next_sy();
        unary_expression(mode, v);
        if (mode == MODE_SKIP) break;
        if (get_symbol_type_class(type, &type_class) < 0) {
            error(errno, "Cannot retrieve symbol type class");
        }
        if (get_symbol_size(type, &type_size) < 0) {
            error(errno, "Cannot retrieve symbol size");
        }
        if (v->remote && v->size == type_size) {
            /* A type cast can be an l-value expression as long as the size does not change */
            int ok = 0;
            switch (type_class) {
            case TYPE_CLASS_CARDINAL:
            case TYPE_CLASS_POINTER:
            case TYPE_CLASS_INTEGER:
            case TYPE_CLASS_ENUMERATION:
                switch (v->type_class) {
                case TYPE_CLASS_CARDINAL:
                case TYPE_CLASS_POINTER:
                case TYPE_CLASS_INTEGER:
                case TYPE_CLASS_ENUMERATION:
                    ok = 1;
                    break;
                }
                break;
            case TYPE_CLASS_REAL:
                ok = v->type_class == TYPE_CLASS_REAL;
                break;
            }
            if (ok) {
                v->type = type;
                v->type_class = type_class;
                break;
            }
        }
        switch (type_class) {
        case TYPE_CLASS_UNKNOWN:
            error(ERR_INV_EXPRESSION, "Unknown type class");
            break;
        case TYPE_CLASS_CARDINAL:
        case TYPE_CLASS_POINTER:
            {
                uint64_t value = to_uns(mode, v);
                v->type = type;
                v->type_class = type_class;
                set_int_value(v, (size_t)type_size, value);
            }
            break;
        case TYPE_CLASS_INTEGER:
        case TYPE_CLASS_ENUMERATION:
            {
                int64_t value = to_int(mode, v);
                v->type = type;
                v->type_class = type_class;
                set_int_value(v, (size_t)type_size, value);
            }
            break;
        case TYPE_CLASS_REAL:
            {
                double value = to_double(mode, v);
                v->type = type;
                v->type_class = type_class;
                set_fp_value(v, (size_t)type_size, value);
            }
            break;
        case TYPE_CLASS_ARRAY:
            if (v->type_class == TYPE_CLASS_POINTER) {
                v->address = (ContextAddress)to_uns(mode, v);
                v->sym = NULL;
                v->reg = NULL;
                v->type = type;
                v->type_class = type_class;
                v->size = type_size;
                v->big_endian = expression_context->big_endian;
                v->remote = 1;
                v->constant = 0;
                v->value = NULL;
            }
            else {
                error(ERR_INV_EXPRESSION, "Invalid type cast: illegal source type");
            }
            break;
        default:
            error(ERR_INV_EXPRESSION, "Invalid type cast: illegal destination type");
            break;
        }
        break;
    }
#endif
    default:
        postfix_expression(mode, v);
        break;
    }
}

static void unary_expression(int mode, Value * v) {
    lazy_unary_expression(mode, v);
#if ENABLE_Symbols
    if (mode != MODE_SKIP && v->sym != NULL && v->size == 0 && get_symbol_size(v->sym, &v->size) < 0) {
        error(errno, "Cannot retrieve symbol size");
    }
#endif
}

static void pm_expression(int mode, Value * v) {
    unary_expression(mode, v);
#if ENABLE_Symbols
    while (text_sy == SY_PM_D || text_sy == SY_PM_R) {
        Value x;
        int sy = text_sy;
        next_sy();
        unary_expression(mode, &x);
        if (x.type == NULL || x.type_class != TYPE_CLASS_MEMBER_PTR) {
            error(ERR_INV_EXPRESSION, "Invalid type: pointer to member expected");
        }
        if (mode != MODE_SKIP) {
            ContextAddress obj = 0;
            ContextAddress ptr = 0;
            ContextAddress addr = 0;
            if (sy == SY_PM_D) {
                if (!v->remote) error(ERR_INV_EXPRESSION, "L-value expected");
                obj = v->address;
            }
            else {
                obj = (ContextAddress)to_uns(mode, v);
            }
            ptr = (ContextAddress)to_uns(mode, &x);
            evaluate_symbol_address(x.type, obj, ptr, &addr);
            set_ctx_word_value(v, addr);
            v->constant = 0;
            if (get_symbol_base_type(x.type, &v->type) < 0) {
                error(ERR_INV_EXPRESSION, "Cannot get pointed type");
            }
            if (get_symbol_type_class(x.type, &v->type_class) < 0) {
                error(ERR_INV_EXPRESSION, "Cannot get pointed type class");
            }
        }
    }
#endif
}

static void multiplicative_expression(int mode, Value * v) {
    pm_expression(mode, v);
    while (text_sy == '*' || text_sy == '/' || text_sy == '%') {
        Value x;
        int sy = text_sy;
        next_sy();
        pm_expression(mode, &x);
        if (mode != MODE_SKIP) {
            if (!is_number(v) || !is_number(&x)) {
                error(ERR_INV_EXPRESSION, "Numeric types expected");
            }
            if (mode == MODE_NORMAL && sy != '*' && to_int(mode, &x) == 0) {
                error(ERR_INV_EXPRESSION, "Dividing by zero");
            }
            if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                double value = 0;
                if (mode == MODE_NORMAL) {
                    switch (sy) {
                    case '*': value = to_double(mode, v) * to_double(mode, &x); break;
                    case '/': value = to_double(mode, v) / to_double(mode, &x); break;
                    default: error(ERR_INV_EXPRESSION, "Invalid type");
                    }
                }
                v->type = NULL;
                v->type_class = TYPE_CLASS_REAL;
                set_fp_value(v, sizeof(double), value);
            }
            else if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                uint64_t value = 0;
                if (mode == MODE_NORMAL) {
                    switch (sy) {
                    case '*': value = to_uns(mode, v) * to_uns(mode, &x); break;
                    case '/': value = to_uns(mode, v) / to_uns(mode, &x); break;
                    case '%': value = to_uns(mode, v) % to_uns(mode, &x); break;
                    }
                }
                v->type = NULL;
                v->type_class = TYPE_CLASS_CARDINAL;
                set_int_value(v, sizeof(uint64_t), value);
            }
            else {
                int64_t value = 0;
                if (mode == MODE_NORMAL) {
                    switch (sy) {
                    case '*': value = to_int(mode, v) * to_int(mode, &x); break;
                    case '/': value = to_int(mode, v) / to_int(mode, &x); break;
                    case '%': value = to_int(mode, v) % to_int(mode, &x); break;
                    }
                }
                v->type = NULL;
                v->type_class = TYPE_CLASS_INTEGER;
                set_int_value(v, sizeof(int64_t), value);
            }
            v->constant = v->constant && x.constant;
        }
    }
}

static void additive_expression(int mode, Value * v) {
    multiplicative_expression(mode, v);
    while (text_sy == '+' || text_sy == '-') {
        Value x;
        int sy = text_sy;
        next_sy();
        multiplicative_expression(mode, &x);
        if (mode != MODE_SKIP) {
            if (v->function) {
                v->type_class = TYPE_CLASS_CARDINAL;
                v->type = NULL;
            }
            if (x.function) {
                x.type_class = TYPE_CLASS_CARDINAL;
                x.type = NULL;
            }
            if (sy == '+' && v->type_class == TYPE_CLASS_ARRAY && x.type_class == TYPE_CLASS_ARRAY) {
                if (mode == MODE_TYPE) {
                    v->remote = 0;
                    v->size = 0;
                    v->value = tmp_alloc_zero((size_t)v->size);
                }
                else {
                    char * value;
                    load_value(v);
                    load_value(&x);
                    v->size = strlen((char *)v->value) + strlen((char *)x.value) + 1;
                    value = (char *)tmp_alloc((size_t)v->size);
                    strcpy(value, (const char *)(v->value));
                    strcat(value, (const char *)(x.value));
                    v->value = value;
                }
                v->type = NULL;
            }
#if ENABLE_Symbols
            else if ((v->type_class == TYPE_CLASS_POINTER || v->type_class == TYPE_CLASS_ARRAY) && is_number(&x)) {
                uint64_t value = 0;
                Symbol * base = NULL;
                ContextAddress size = 0;
                if (v->type == NULL || get_symbol_base_type(v->type, &base) < 0 ||
                    base == NULL || get_symbol_size(base, &size) < 0 || size == 0) {
                    error(ERR_INV_EXPRESSION, "Unknown pointer base type size");
                }
                switch (sy) {
                case '+': value = to_uns(mode, v) + to_uns(mode, &x) * size; break;
                case '-': value = to_uns(mode, v) - to_uns(mode, &x) * size; break;
                }
                if (v->type_class == TYPE_CLASS_ARRAY) {
                    if (get_array_symbol(base, 0, &v->type) < 0 ||
                        get_symbol_size(v->type, &v->size) < 0) {
                        error(errno, "Cannot cast to pointer");
                    }
                    v->type_class = TYPE_CLASS_POINTER;
                }
                set_int_value(v, (size_t)v->size, value);
            }
            else if (is_number(v) && (x.type_class == TYPE_CLASS_POINTER || x.type_class == TYPE_CLASS_ARRAY) && sy == '+') {
                uint64_t value = 0;
                Symbol * base = NULL;
                ContextAddress size = 0;
                if (x.type == NULL || get_symbol_base_type(x.type, &base) < 0 ||
                    base == NULL || get_symbol_size(base, &size) < 0 || size == 0) {
                    error(ERR_INV_EXPRESSION, "Unknown pointer base type size");
                }
                value = to_uns(mode, &x) + to_uns(mode, v) * size;
                v->type = x.type;
                if (x.type_class == TYPE_CLASS_ARRAY) {
                    if (get_array_symbol(base, 0, &v->type) < 0 ||
                        get_symbol_size(v->type, &v->size) < 0) {
                        error(errno, "Cannot cast to pointer");
                    }
                }
                v->type_class = TYPE_CLASS_POINTER;
                set_int_value(v, (size_t)x.size, value);
            }
#endif
            else if (!is_number(v) || !is_number(&x)) {
                error(ERR_INV_EXPRESSION, "Numeric types expected");
            }
            else if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                double value = 0;
                switch (sy) {
                case '+': value = to_double(mode, v) + to_double(mode, &x); break;
                case '-': value = to_double(mode, v) - to_double(mode, &x); break;
                }
                v->type = NULL;
                v->type_class = TYPE_CLASS_REAL;
                set_fp_value(v, sizeof(double), value);
            }
            else if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                uint64_t value = 0;
                switch (sy) {
                case '+': value = to_uns(mode, v) + to_uns(mode, &x); break;
                case '-': value = to_uns(mode, v) - to_uns(mode, &x); break;
                }
                v->type = NULL;
                v->type_class = TYPE_CLASS_CARDINAL;
                set_int_value(v, sizeof(uint64_t), value);
            }
            else {
                int64_t value = 0;
                switch (sy) {
                case '+': value = to_int(mode, v) + to_int(mode, &x); break;
                case '-': value = to_int(mode, v) - to_int(mode, &x); break;
                }
                v->type = NULL;
                v->type_class = TYPE_CLASS_INTEGER;
                set_int_value(v, sizeof(int64_t), value);
            }
            v->constant = v->constant && x.constant;
        }
    }
}

static void shift_expression(int mode, Value * v) {
    additive_expression(mode, v);
    while (text_sy == SY_SHL || text_sy == SY_SHR) {
        Value x;
        int sy = text_sy;
        next_sy();
        additive_expression(mode, &x);
        if (mode != MODE_SKIP) {
            uint64_t value = 0;
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            if (x.type_class != TYPE_CLASS_CARDINAL && to_int(mode, &x) < 0) {
                if (v->type_class == TYPE_CLASS_CARDINAL) {
                    switch (sy) {
                    case SY_SHL: value = to_uns(mode, v) >> -to_int(mode, &x); break;
                    case SY_SHR: value = to_uns(mode, v) << -to_int(mode, &x); break;
                    }
                }
                else {
                    switch (sy) {
                    case SY_SHL: value = to_int(mode, v) >> -to_int(mode, &x); break;
                    case SY_SHR: value = to_int(mode, v) << -to_int(mode, &x); break;
                    }
                    v->type_class = TYPE_CLASS_INTEGER;
                }
            }
            else {
                if (v->type_class == TYPE_CLASS_CARDINAL) {
                    switch (sy) {
                    case SY_SHL: value = to_uns(mode, v) << to_uns(mode, &x); break;
                    case SY_SHR: value = to_uns(mode, v) >> to_uns(mode, &x); break;
                    }
                }
                else {
                    switch (sy) {
                    case SY_SHL: value = to_int(mode, v) << to_uns(mode, &x); break;
                    case SY_SHR: value = to_int(mode, v) >> to_uns(mode, &x); break;
                    }
                    v->type_class = TYPE_CLASS_INTEGER;
                }
            }
            v->type = NULL;
            v->constant = v->constant && x.constant;
            set_int_value(v, sizeof(uint64_t), value);
        }
    }
}

static void relational_expression(int mode, Value * v) {
    shift_expression(mode, v);
    while (text_sy == '<' || text_sy == '>' || text_sy == SY_LEQ || text_sy == SY_GEQ) {
        Value x;
        int sy = text_sy;
        next_sy();
        shift_expression(mode, &x);
        if (mode != MODE_SKIP) {
            uint32_t value = 0;
            if (v->type_class == TYPE_CLASS_ARRAY && x.type_class == TYPE_CLASS_ARRAY) {
                int n = 0;
                load_value(v);
                load_value(&x);
                n = strcmp((char *)v->value, (char *)x.value);
                switch (sy) {
                case '<': value = n < 0; break;
                case '>': value = n > 0; break;
                case SY_LEQ: value = n <= 0; break;
                case SY_GEQ: value = n >= 0; break;
                }
            }
            else if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                switch (sy) {
                case '<': value = to_double(mode, v) < to_double(mode, &x); break;
                case '>': value = to_double(mode, v) > to_double(mode, &x); break;
                case SY_LEQ: value = to_double(mode, v) <= to_double(mode, &x); break;
                case SY_GEQ: value = to_double(mode, v) >= to_double(mode, &x); break;
                }
            }
            else if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                switch (sy) {
                case '<': value = to_uns(mode, v) < to_uns(mode, &x); break;
                case '>': value = to_uns(mode, v) > to_uns(mode, &x); break;
                case SY_LEQ: value = to_uns(mode, v) <= to_uns(mode, &x); break;
                case SY_GEQ: value = to_uns(mode, v) >= to_uns(mode, &x); break;
                }
            }
            else {
                switch (sy) {
                case '<': value = to_int(mode, v) < to_int(mode, &x); break;
                case '>': value = to_int(mode, v) > to_int(mode, &x); break;
                case SY_LEQ: value = to_int(mode, v) <= to_int(mode, &x); break;
                case SY_GEQ: value = to_int(mode, v) >= to_int(mode, &x); break;
                }
            }
            if (mode != MODE_NORMAL) value = 0;
            v->type_class = TYPE_CLASS_INTEGER;
            v->type = NULL;
            v->constant = v->constant && x.constant;
            set_int_value(v, sizeof(uint32_t), value);
        }
    }
}

static void equality_expression(int mode, Value * v) {
    relational_expression(mode, v);
    while (text_sy == SY_EQU || text_sy == SY_NEQ) {
        Value x;
        int sy = text_sy;
        next_sy();
        relational_expression(mode, &x);
        if (mode != MODE_SKIP) {
            uint32_t value = 0;
            if (v->type_class == TYPE_CLASS_ARRAY && x.type_class == TYPE_CLASS_ARRAY) {
                load_value(v);
                load_value(&x);
                value = strcmp((char *)v->value, (char *)x.value) == 0;
            }
            else if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                value = to_double(mode, v) == to_double(mode, &x);
            }
            else {
                value = to_int(mode, v) == to_int(mode, &x);
            }
            if (sy == SY_NEQ) value = !value;
            if (mode != MODE_NORMAL) value = 0;
            v->type_class = TYPE_CLASS_INTEGER;
            v->type = NULL;
            v->constant = v->constant && x.constant;
            set_int_value(v, sizeof(uint32_t), value);
        }
    }
}

static void and_expression(int mode, Value * v) {
    equality_expression(mode, v);
    while (text_sy == '&') {
        Value x;
        next_sy();
        equality_expression(mode, &x);
        if (mode != MODE_SKIP) {
            int64_t value = 0;
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                v->type_class = TYPE_CLASS_CARDINAL;
                value = to_uns(mode, v) & to_uns(mode, &x);
            }
            else {
                v->type_class = TYPE_CLASS_INTEGER;
                value = to_int(mode, v) & to_int(mode, &x);
            }
            if (mode != MODE_NORMAL) value = 0;
            v->type = NULL;
            v->constant = v->constant && x.constant;
            set_int_value(v, sizeof(int64_t), value);
        }
    }
}

static void exclusive_or_expression(int mode, Value * v) {
    and_expression(mode, v);
    while (text_sy == '^') {
        Value x;
        next_sy();
        and_expression(mode, &x);
        if (mode != MODE_SKIP) {
            int64_t value = 0;
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                v->type_class = TYPE_CLASS_CARDINAL;
                value = to_uns(mode, v) ^ to_uns(mode, &x);
            }
            else {
                v->type_class = TYPE_CLASS_INTEGER;
                value = to_int(mode, v) ^ to_int(mode, &x);
            }
            if (mode != MODE_NORMAL) value = 0;
            v->type = NULL;
            v->constant = v->constant && x.constant;
            set_int_value(v, sizeof(int64_t), value);
        }
    }
}

static void inclusive_or_expression(int mode, Value * v) {
    exclusive_or_expression(mode, v);
    while (text_sy == '|') {
        Value x;
        next_sy();
        exclusive_or_expression(mode, &x);
        if (mode != MODE_SKIP) {
            int64_t value = 0;
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                v->type_class = TYPE_CLASS_CARDINAL;
                value = to_uns(mode, v) | to_uns(mode, &x);
            }
            else {
                v->type_class = TYPE_CLASS_INTEGER;
                value = to_int(mode, v) | to_int(mode, &x);
            }
            if (mode != MODE_NORMAL) value = 0;
            v->type = NULL;
            v->constant = v->constant && x.constant;
            set_int_value(v, sizeof(int64_t), value);
        }
    }
}

static void logical_and_expression(int mode, Value * v) {
    inclusive_or_expression(mode, v);
    while (text_sy == SY_AND) {
        Value x;
        int b = to_boolean(mode, v);
        next_sy();
        inclusive_or_expression(b ? mode : MODE_SKIP, &x);
        if (b) {
            if (!v->constant) x.constant = 0;
            *v = x;
        }
    }
}

static void logical_or_expression(int mode, Value * v) {
    logical_and_expression(mode, v);
    while (text_sy == SY_OR) {
        Value x;
        int b = to_boolean(mode, v);
        next_sy();
        logical_and_expression(!b ? mode : MODE_SKIP, &x);
        if (!b) {
            if (!v->constant) x.constant = 0;
            *v = x;
        }
    }
}

static void conditional_expression(int mode, Value * v) {
    logical_or_expression(mode, v);
    if (text_sy == '?') {
        Value x;
        Value y;
        int b = to_boolean(mode, v);
        next_sy();
        expression(b ? mode : MODE_SKIP, &x);
        if (text_sy != ':') error(ERR_INV_EXPRESSION, "Missing ':'");
        next_sy();
        conditional_expression(!b ? mode : MODE_SKIP, &y);
        if (!v->constant) x.constant = y.constant = 0;
        *v = b ? x : y;
    }
}

static void expression(int mode, Value * v) {
    /* TODO: assignments in expressions */
    conditional_expression(mode, v);
}

static int evaluate_script(int mode, char * s, int load, Value * v) {
    Trap trap;

    expression_has_func_call = 0;
    if (set_trap(&trap)) {
        if (s == NULL || *s == 0) str_exception(ERR_INV_EXPRESSION, "Empty expression");
        text = s;
        text_pos = 0;
        text_len = strlen(s) + 1;
        next_ch();
        next_sy();
        expression(mode, v);
        if (text_sy != 0) error(ERR_INV_EXPRESSION, "Illegal characters at the end of expression");
        if (load) load_value(v);
        clear_trap(&trap);
    }

#if ENABLE_FuncCallInjection
    if (get_error_code(trap.error) != ERR_CACHE_MISS) {
        unsigned id = cache_transaction_id();
        LINK * l = func_call_state.next;
        while (l != &func_call_state) {
            FuncCallState * state = link_all2fc(l);
            l = l->next;
            if (state->id == id) {
                state->committed = 1;
                if (state->regs_cnt == 0) free_funccall_state(state);
            }
        }
    }
#endif /* ENABLE_FuncCallInjection */

    if (trap.error) {
        errno = trap.error;
        return -1;
    }

    return 0;
}

static int evaluate_type(Context * ctx, int frame, ContextAddress addr, char * s, Value * v) {
    expression_context = ctx;
    expression_frame = frame;
    expression_addr = addr;
    return evaluate_script(MODE_TYPE, s, 0, v);
}

int evaluate_expression(Context * ctx, int frame, ContextAddress addr, char * s, int load, Value * v) {
    expression_context = ctx;
    expression_frame = frame;
    expression_addr = addr;
    return evaluate_script(MODE_NORMAL, s, load, v);
}

int value_to_boolean(Value * v, int * res) {
    Trap trap;
    if (!set_trap(&trap)) return -1;
    *res = to_boolean(MODE_NORMAL, v);
    clear_trap(&trap);
    return 0;
}

int value_to_address(Value * v, ContextAddress * res) {
    Trap trap;
    if (!set_trap(&trap)) return -1;
    *res = (ContextAddress)to_uns(MODE_NORMAL, v);
    clear_trap(&trap);
    return 0;
}

int value_to_signed(Value * v, int64_t *res) {
    Trap trap;
    if (!set_trap(&trap)) return -1;
    *res = to_int(MODE_NORMAL, v);
    clear_trap(&trap);
    return 0;
}

int value_to_unsigned(Value * v, uint64_t *res) {
    Trap trap;
    if (!set_trap(&trap)) return -1;
    *res = to_uns(MODE_NORMAL, v);
    clear_trap(&trap);
    return 0;
}

int value_to_double(Value * v, double *res) {
    Trap trap;
    if (!set_trap(&trap)) return -1;
    *res = to_double(MODE_NORMAL, v);
    clear_trap(&trap);
    return 0;
}

/********************** Commands **************************/

typedef struct CommandArgs {
    char token[256];
    char id[256];
} CommandArgs;

typedef struct CommandCreateArgs {
    char token[256];
    char id[256];
    char language[256];
    char * script;
} CommandCreateArgs;

typedef struct CommandAssignArgs {
    char token[256];
    char id[256];
    char * value_buf;
    size_t value_size;
} CommandAssignArgs;

typedef struct Expression {
    LINK link_all;
    LINK link_id;
    char id[256];
    char var_id[256];
    char parent[256];
    char language[256];
    Channel * channel;
    char * script;
    int can_assign;
    int has_func_call;
    ContextAddress size;
    int type_class;
    char type[256];
} Expression;

#define link_all2exp(A)  ((Expression *)((char *)(A) - offsetof(Expression, link_all)))
#define link_id2exp(A)   ((Expression *)((char *)(A) - offsetof(Expression, link_id)))

#define ID2EXP_HASH_SIZE (32 * MEM_USAGE_FACTOR - 1)

static LINK expressions = TCF_LIST_INIT(expressions);
static LINK id2exp[ID2EXP_HASH_SIZE];

#define MAX_SYM_NAME 1024

static const char * EXPRESSIONS = "Expressions";
static unsigned expr_id_cnt = 0;

#define expression_hash(id) ((unsigned)atoi(id + 4) % ID2EXP_HASH_SIZE)

static Expression * find_expression(char * id) {
    if (id[0] == 'E' && id[1] == 'X' && id[2] == 'P' && id[3] == 'R') {
        unsigned hash = expression_hash(id);
        LINK * l = id2exp[hash].next;
        while (l != &id2exp[hash]) {
            Expression * e = link_id2exp(l);
            l = l->next;
            if (strcmp(e->id, id) == 0) return e;
        }
    }
    return NULL;
}

static int symbol_to_expression(char * expr_id, char * parent, char * sym_id, Expression ** res) {
#if ENABLE_Symbols
    Symbol * sym = NULL;
    Symbol * type = NULL;
    int sym_class = 0;
    size_t script_len = strlen(sym_id) + 8;
    char * script = (char *)tmp_alloc(script_len);
    Expression * expr = (Expression *)tmp_alloc_zero(sizeof(Expression));

    strlcpy(expr->id, expr_id, sizeof(expr->id));
    strlcpy(expr->var_id, sym_id, sizeof(expr->var_id));
    strlcpy(expr->parent, parent, sizeof(expr->parent));

    if (id2symbol(sym_id, &sym) < 0) return -1;

    snprintf(script, script_len, "${%s}", sym_id);
    expr->script = script;

    get_symbol_type_class(sym, &expr->type_class);
    get_symbol_size(sym, &expr->size);

    if (get_symbol_class(sym, &sym_class) == 0) {
        expr->can_assign = sym_class == SYM_CLASS_REFERENCE;
    }

    if (get_symbol_type(sym, &type) == 0 && type != NULL) {
        strlcpy(expr->type, symbol2id(type), sizeof(expr->type));
    }

    *res = expr;
    return 0;
#else
    errno = ERR_UNSUPPORTED;
    return -1;
#endif
}

static int expression_context_id(char * id, Context ** ctx, int * frame, Expression ** expr) {
    int err = 0;
    Expression * e = NULL;

    if (id[0] == 'S') {
        char parent[256];
        char * s = id + 1;
        size_t i = 0;
        while (*s && i < sizeof(parent) - 1) {
            char ch = *s++;
            if (ch == '.') {
                if (*s == '.') {
                    parent[i++] = *s++;
                    continue;
                }
                break;
            }
            parent[i++] = ch;
        }
        parent[i] = 0;
        if (symbol_to_expression(id, parent, s, &e) < 0) err = errno;
    }
    else if ((e = find_expression(id)) == NULL) {
        err = ERR_INV_CONTEXT;
    }

    if (!err) {
        if ((*ctx = id2ctx(e->parent)) != NULL) {
            *frame = context_has_state(*ctx) ? STACK_TOP_FRAME : STACK_NO_FRAME;
        }
        else if (id2frame(e->parent, ctx, frame) < 0) {
            err = errno;
        }
    }

    if (err) {
        errno = err;
        return -1;
    }

    *expr = e;
    return 0;
}

static void write_context(OutputStream * out, Expression * expr) {
    write_stream(out, '{');
    json_write_string(out, "ID");
    write_stream(out, ':');
    json_write_string(out, expr->id);

    write_stream(out, ',');

    json_write_string(out, "ParentID");
    write_stream(out, ':');
    json_write_string(out, expr->parent);

    if (expr->var_id[0]) {
        write_stream(out, ',');

        json_write_string(out, "SymbolID");
        write_stream(out, ':');
        json_write_string(out, expr->var_id);
    }

    write_stream(out, ',');

    json_write_string(out, "Expression");
    write_stream(out, ':');
    json_write_string(out, expr->script);

    if (expr->can_assign) {
        write_stream(out, ',');

        json_write_string(out, "CanAssign");
        write_stream(out, ':');
        json_write_boolean(out, expr->can_assign);
    }

    if (expr->has_func_call) {
        write_stream(out, ',');

        json_write_string(out, "HasFuncCall");
        write_stream(out, ':');
        json_write_boolean(out, expr->has_func_call);
    }

    if (expr->type_class != TYPE_CLASS_UNKNOWN) {
        write_stream(out, ',');

        json_write_string(out, "Class");
        write_stream(out, ':');
        json_write_long(out, expr->type_class);
    }

    if (expr->type[0]) {
        write_stream(out, ',');

        json_write_string(out, "Type");
        write_stream(out, ':');
        json_write_string(out, expr->type);
    }

    write_stream(out, ',');

    json_write_string(out, "Size");
    write_stream(out, ':');
    json_write_uint64(out, expr->size);

    write_stream(out, '}');
}

static void get_context_cache_client(void * x) {
    CommandArgs * args = (CommandArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Expression * expr = NULL;
    int err = 0;

    if (expression_context_id(args->id, &ctx, &frame, &expr) < 0) err = errno;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        write_context(&c->out, expr);
        write_stream(&c->out, 0);
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_get_context(char * token, Channel * c) {
    CommandArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(get_context_cache_client, c, &args, sizeof(args));
}

#if ENABLE_Symbols

static int sym_cnt = 0;
static int sym_max = 0;
static Symbol ** sym_buf = NULL;

static void get_children_callback(void * x, Symbol * symbol) {
    if (sym_cnt >= sym_max) {
        sym_max += 8;
        sym_buf = (Symbol **)loc_realloc(sym_buf, sizeof(Symbol *) * sym_max);
    }
    sym_buf[sym_cnt++] = symbol;
}

#endif

static void get_children_cache_client(void * x) {
    CommandArgs * args = (CommandArgs *)x;
    Channel * c = cache_channel();
    int err = 0;

    /* TODO: Expressions.getChildren - structures */
#if ENABLE_Symbols
    char parent_id[256];
    {
        Context * ctx;
        int frame = STACK_NO_FRAME;

        sym_cnt = 0;

        if ((ctx = id2ctx(args->id)) != NULL && context_has_state(ctx)) {
            frame = get_top_frame(ctx);
            strlcpy(parent_id, frame2id(ctx, frame), sizeof(parent_id));
        }
        else if (id2frame(args->id, &ctx, &frame) == 0) {
            strlcpy(parent_id, args->id, sizeof(parent_id));
        }
        else {
            ctx = NULL;
        }

        if (ctx != NULL && err == 0 && enumerate_symbols(
                ctx, frame, get_children_callback, &args) < 0) err = errno;
    }
#else
    err = ERR_UNSUPPORTED;
#endif

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);

    write_errno(&c->out, err);

    write_stream(&c->out, '[');
#if ENABLE_Symbols
    {
        int i;
        for (i = 0; i < sym_cnt; i++) {
            const char * s = parent_id;
            if (i > 0) write_stream(&c->out, ',');
            write_stream(&c->out, '"');
            write_stream(&c->out, 'S');
            while (*s) {
                if (*s == '.') write_stream(&c->out, '.');
                json_write_char(&c->out, *s++);
            }
            write_stream(&c->out, '.');
            s = symbol2id(sym_buf[i]);
            while (*s) json_write_char(&c->out, *s++);
            write_stream(&c->out, '"');
        }
    }
#endif
    write_stream(&c->out, ']');
    write_stream(&c->out, 0);

    write_stream(&c->out, MARKER_EOM);
}

static void command_get_children(char * token, Channel * c) {
    CommandArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(get_children_cache_client, c, &args, sizeof(args));
}

static void command_create_cache_client(void * x) {
    CommandCreateArgs * args = (CommandCreateArgs *)x;
    Expression * e;
    Expression buf;
    Channel * c = cache_channel();
    int frame = STACK_NO_FRAME;
    int err = 0;

    memset(e = &buf, 0, sizeof(buf));
    do snprintf(e->id, sizeof(e->id), "EXPR%d", expr_id_cnt++);
    while (find_expression(e->id) != NULL);
    strlcpy(e->parent, args->id, sizeof(e->parent));
    strlcpy(e->language, args->language, sizeof(e->language));
    e->channel = c;
    e->script = args->script;

    if (!err) {
        Value value;
        Context * ctx = NULL;
        memset(&value, 0, sizeof(value));
        if ((ctx = id2ctx(e->parent)) != NULL) {
            frame = context_has_state(ctx) ? STACK_TOP_FRAME : STACK_NO_FRAME;
        }
        else if (id2frame(e->parent, &ctx, &frame) < 0) {
            err = errno;
        }
        if (!err && evaluate_type(ctx, frame, 0, e->script, &value) < 0) err = errno;
        if (!err) {
            e->can_assign = value.remote;
            e->has_func_call = expression_has_func_call;
            e->type_class = value.type_class;
            e->size = value.size;
#if ENABLE_Symbols
            if (value.type != NULL) strlcpy(e->type, symbol2id(value.type), sizeof(e->type));
#endif
        }
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (err) {
        write_stringz(&c->out, "null");
        loc_free(e->script);
    }
    else {
        *(e = (Expression *)loc_alloc(sizeof(Expression))) = buf;
        list_add_last(&e->link_all, &expressions);
        list_add_last(&e->link_id, id2exp + expression_hash(e->id));
        write_context(&c->out, e);
        write_stream(&c->out, 0);
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_create(char * token, Channel * c) {
    CommandCreateArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    json_test_char(&c->inp, MARKER_EOA);
    json_read_string(&c->inp, args.language, sizeof(args.language));
    json_test_char(&c->inp, MARKER_EOA);
    args.script = json_read_alloc_string(&c->inp);
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_create_cache_client, c, &args, sizeof(args));
}

static void command_evaluate_cache_client(void * x) {
    CommandCreateArgs * args = (CommandCreateArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Expression * expr = NULL;
    int value_ok = 0;
    Value value;
    int err = 0;

    memset(&value, 0, sizeof(value));
    if (expression_context_id(args->id, &ctx, &frame, &expr) < 0) err = errno;
    if (!err && frame != STACK_NO_FRAME && !ctx->stopped) err = ERR_IS_RUNNING;
    if (!err && evaluate_expression(ctx, frame, 0, expr->script, 0, &value) < 0) err = errno;
    if (value.size >= 0x100000) err = ERR_BUFFER_OVERFLOW;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        JsonWriteBinaryState state;

        value_ok = 1;
        json_write_binary_start(&state, &c->out, (size_t)value.size);
        if (!value.remote) {
            json_write_binary_data(&state, value.value, (size_t)value.size);
        }
        else {
            char buf[256];
            size_t offs = 0;
            while (offs < (size_t)value.size) {
                int size = (size_t)value.size - offs;
                if (size > (int)sizeof(buf)) size = (int)sizeof(buf);
                memset(buf, 0, size);
                if (!err && context_read_mem(ctx, value.address + offs, buf, size) < 0)
                    err = set_errno(errno, "Cannot read target memory");
                json_write_binary_data(&state, buf, size);
                offs += size;
            }
        }
        json_write_binary_end(&state);
        write_stream(&c->out, 0);
    }
    write_errno(&c->out, err);
    if (!value_ok) {
        write_stringz(&c->out, "null");
    }
    else {
        int cnt = 0;
        write_stream(&c->out, '{');

        if (value.type_class != TYPE_CLASS_UNKNOWN) {
            json_write_string(&c->out, "Class");
            write_stream(&c->out, ':');
            json_write_long(&c->out, value.type_class);
            cnt++;
        }

#if ENABLE_Symbols
        if (value.type != NULL) {
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, "Type");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(value.type));
            cnt++;
        }

        if (value.sym != NULL) {
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, "Symbol");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(value.sym));
            cnt++;
        }
#endif
        if (value.reg != NULL) {
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, "Register");
            write_stream(&c->out, ':');
            json_write_string(&c->out, register2id(ctx, frame, value.reg));
            cnt++;
        }

        if (value.remote) {
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, "Address");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, value.address);
            cnt++;
        }

        if (value.big_endian) {
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, "BigEndian");
            write_stream(&c->out, ':');
            json_write_boolean(&c->out, 1);
            cnt++;
        }

        write_stream(&c->out, '}');
        write_stream(&c->out, 0);
    }
    write_stream(&c->out, MARKER_EOM);
}

static void command_evaluate(char * token, Channel * c) {
    CommandArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_evaluate_cache_client, c, &args, sizeof(args));
}

static void command_assign_cache_client(void * x) {
    CommandAssignArgs * args = (CommandAssignArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Expression * expr = NULL;
    Value value;
    int err = 0;

    memset(&value, 0, sizeof(value));
    if (expression_context_id(args->id, &ctx, &frame, &expr) < 0) err = errno;
    if (!err && frame != STACK_NO_FRAME && !ctx->stopped) err = ERR_IS_RUNNING;
    if (!err && evaluate_expression(ctx, frame, 0, expr->script, 0, &value) < 0) err = errno;
    if (!err) {
        if (value.reg != NULL) {
            StackFrame * info = NULL;
            if (get_frame_info(ctx, frame, &info) < 0) err = errno;
            if (!err && write_reg_bytes(info, value.reg, 0, args->value_size, (uint8_t *)args->value_buf) < 0) err = errno;
#if SERVICE_Registers
            if (!err) send_event_register_changed(register2id(ctx, frame, value.reg));
#endif
        }
        else if (value.remote) {
            if (context_write_mem(ctx, value.address, args->value_buf, args->value_size) < 0) err = errno;
#if SERVICE_Memory
            if (!err) send_event_memory_changed(ctx, value.address, args->value_size);
#endif
        }
        else {
            err = ERR_INV_EXPRESSION;
        }
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);
    write_stream(&c->out, MARKER_EOM);
    loc_free(args->value_buf);
}

static void command_assign(char * token, Channel * c) {
    CommandAssignArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    json_test_char(&c->inp, MARKER_EOA);
    args.value_buf = json_read_alloc_binary(&c->inp, &args.value_size);
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_assign_cache_client, c, &args, sizeof(args));
}

static void command_dispose(char * token, Channel * c) {
    char id[256];
    int err = 0;
    Expression * e;

    json_read_string(&c->inp, id, sizeof(id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    e = find_expression(id);
    if (e != NULL) {
        list_remove(&e->link_all);
        list_remove(&e->link_id);
        loc_free(e->script);
        loc_free(e);
    }
    else {
        err = ERR_INV_CONTEXT;
    }

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, err);
    write_stream(&c->out, MARKER_EOM);
}

static void on_channel_close(Channel * c) {
    LINK * l = expressions.next;
    while (l != &expressions) {
        Expression * e = link_all2exp(l);
        l = l->next;
        if (e->channel == c) {
            list_remove(&e->link_all);
            list_remove(&e->link_id);
            loc_free(e->script);
            loc_free(e);
        }
    }
}

void add_identifier_callback(ExpressionIdentifierCallBack * callback) {
    assert(id_callback_cnt < MAX_ID_CALLBACKS);
    id_callbacks[id_callback_cnt++] = callback;
}

#if ENABLE_FuncCallInjection
static void context_intercepted(Context * ctx, void * args) {
    LINK * l = func_call_state.next;
    while (l != &func_call_state) {
        FuncCallState * state = link_all2fc(l);
        l = l->next;
        if (state->ctx == ctx && !state->intercepted) {
            state->intercepted = 1;
            if (!state->finished && state->error == NULL) {
                state->error = get_error_report(set_errno(ERR_OTHER,
                    "Intercepted while executing injected function call"));
            }
            cache_notify(&state->cache);
        }
    }
}
#endif

void ini_expressions_service(Protocol * proto) {
    unsigned i;
#if ENABLE_FuncCallInjection
    static RunControlEventListener rc_listener = { context_intercepted, NULL };
    add_run_control_event_listener(&rc_listener, NULL);
#endif
    for (i = 0; i < ID2EXP_HASH_SIZE; i++) list_init(id2exp + i);
    add_channel_close_listener(on_channel_close);
    add_command_handler(proto, EXPRESSIONS, "getContext", command_get_context);
    add_command_handler(proto, EXPRESSIONS, "getChildren", command_get_children);
    add_command_handler(proto, EXPRESSIONS, "create", command_create);
    add_command_handler(proto, EXPRESSIONS, "evaluate", command_evaluate);
    add_command_handler(proto, EXPRESSIONS, "assign", command_assign);
    add_command_handler(proto, EXPRESSIONS, "dispose", command_dispose);

    big_endian = big_endian_host();
}

#endif  /* if SERVICE_Expressions */
