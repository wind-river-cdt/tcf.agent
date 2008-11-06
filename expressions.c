/*******************************************************************************
 * Copyright (c) 2007, 2008 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * Expression evaluation service.
 */

#include "mdep.h"
#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "myalloc.h"
#include "exceptions.h"
#include "stacktrace.h"
#include "symbols.h"
#include "breakpoints.h"
#include "expressions.h"

#define STR_POOL_SIZE 1024

struct StringValue {
    struct StringValue * next;
    char buf[1];
};

typedef struct StringValue StringValue;

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

static char * text = NULL;
static int text_pos = 0;
static int text_len = 0;
static int text_ch = 0;
static int text_sy = 0;
static Value text_val;

static char str_pool[STR_POOL_SIZE];
static int str_pool_cnt = 0;
static StringValue * str_alloc_list = NULL;

static Context * expression_context = NULL;
static int expression_frame = STACK_NO_FRAME;

static void * alloc_str(int size) {
    if (str_pool_cnt + size <= STR_POOL_SIZE) {
        char * s = str_pool + str_pool_cnt;
        str_pool_cnt += size;
        return s;
    }
    else {
        StringValue * s = (StringValue *)loc_alloc(sizeof(StringValue) + size - 1);
        s->next = str_alloc_list;
        str_alloc_list = s;
        return s->buf;
    }
}

void string_value(Value * v, char * str) {
    memset(v, 0, sizeof(Value));
    v->type_class = TYPE_CLASS_ARRAY;
    if (str != NULL) {
        v->size = strlen(str) + 1;
        v->value = alloc_str(v->size);
        memcpy(v->value, str, v->size);
    }
}

static void error(int no, char * msg) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s, text pos %d", msg, text_pos);
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
        case ':':
        case '?':
        case ',':
        case '.':
            text_sy = ch;
            return;
        case '-':
            if (text_ch == '>') {
                next_ch();
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
            text_val.type_class = TYPE_CLASS_INTEGER;
            text_val.size = sizeof(int);
            text_val.value = alloc_str(text_val.size);
            text_val.remote = 0;
            *(int *)text_val.value = next_char_val();
            if (text_ch != '\'') error(ERR_INV_EXPRESSION, "Missing 'single quote'");
            next_ch();
            text_sy = SY_VAL;
            return;
        case '"':
            {
                int len = 0;
                int cnt = 0;
                int pos = text_pos;
                while (text_ch != '"') {
                    next_char_val();
                    len++;
                }
                text_val.type_class = TYPE_CLASS_ARRAY;
                text_val.size = len + 1;
                text_val.value = alloc_str(text_val.size);
                text_val.remote = 0;
                text_pos = pos - 1;
                next_ch();
                while (text_ch != '"') {
                    ((char *)text_val.value)[cnt++] = next_char_val();
                }
                assert(cnt == len);
                ((char *)text_val.value)[cnt] = 0;
                next_ch();
                text_sy = SY_VAL;
            }
            return;
        case '0':
            if (text_ch == 'x') {
                uns64 value = 0;
                next_ch();
                text_val.type_class = TYPE_CLASS_CARDINAL;
                text_val.size = sizeof(uns64);
                text_val.value = alloc_str(text_val.size);
                text_val.remote = 0;
                while (text_ch >= '0' && text_ch <= '9' ||
                        text_ch >= 'A' && text_ch <= 'F' ||
                        text_ch >= 'a' && text_ch <= 'f') {
                    value = (value << 4) | next_hex();
                }
                *(uns64 *)text_val.value = value;
            }
            else {
                int64 value = 0;
                text_val.type_class = TYPE_CLASS_INTEGER;
                text_val.size = sizeof(int64);
                text_val.value = alloc_str(text_val.size);
                text_val.remote = 0;
                while (text_ch >= '0' && text_ch <= '7') {
                    value = (value << 3) | next_oct();
                }
                *(int64 *)text_val.value = value;
            }
            text_sy = SY_VAL;
            return;
        default:
            if (ch >= '0' && ch <= '9') {
                int64 value = ch - '0';
                text_val.type_class = TYPE_CLASS_INTEGER;
                text_val.size = sizeof(int64);
                text_val.value = alloc_str(text_val.size);
                text_val.remote = 0;
                while (text_ch >= '0' && text_ch <= '9') {
                    value = (value * 10) + next_dec();
                }
                *(int64 *)text_val.value = value;
                text_sy = SY_VAL;
                return;
            }
            if (is_name_character(ch)) {
                int len = 1;
                int cnt = 0;
                int pos = text_pos - 1;
                while (is_name_character(text_ch)) {
                    len++;
                    next_ch();
                }
                text_val.type_class = TYPE_CLASS_ARRAY;
                text_val.size = len + 1;
                text_val.value = alloc_str(text_val.size);
                text_val.remote = 0;
                text_pos = pos - 1;
                next_ch();
                while (is_name_character(text_ch)) {
                    ((char *)text_val.value)[cnt++] = text_ch;
                    next_ch();
                }
                assert(cnt == len);
                ((char *)text_val.value)[cnt] = 0;
                text_sy = SY_ID;
                return;
            }
            error(ERR_INV_EXPRESSION, "Illegal character");
            break;
        }
    }
}

static void identifier(char * name, Value * v) {
    if (v == NULL) return;
    memset(v, 0, sizeof(Value));
    if (expression_context == NULL) {
        exception(ERR_INV_CONTEXT);
    }
    if (strcmp(name, "$thread") == 0) {
        if (context_has_state(expression_context)) {
            string_value(v, thread_id(expression_context));
        }
        else {
            string_value(v, container_id(expression_context));
        }
        return;
    }
#if SERVICE_Symbols
    {
        Symbol sym;
        if (find_symbol(expression_context, expression_frame, name, &sym) < 0) {
            error(errno, "Invalid identifier");
        }
        else {
            if (get_symbol_type(&sym, &v->type) < 0) {
                error(errno, "Cannot retrieve symbol type");
            }
            if (get_symbol_type_class(&sym, &v->type_class) < 0) {
                error(errno, "Cannot retrieve symbol type class");
            }
            switch (sym.sym_class) {
            case SYM_CLASS_VALUE:
                {
                    size_t size = 0;
                    void * value = NULL;
                    if (get_symbol_value(&sym, &value, &size) < 0) {
                        error(errno, "Cannot retrieve symbol value");
                    }
                    v->size = size;
                    v->value = alloc_str(v->size);
                    v->remote = 0;
                    memcpy(v->value, value, size);
                    loc_free(value);
                }
                return;
            case SYM_CLASS_REFERENCE:
                v->remote = 1;
                if (get_symbol_size(&sym, &v->size) < 0) {
                    error(errno, "Cannot retrieve symbol size");
                }
                if (get_symbol_address(&sym, expression_frame, &v->address) < 0) {
                    error(errno, "Cannot retrieve symbol address");
                }
                return;
            case SYM_CLASS_FUNCTION:
                v->type_class = TYPE_CLASS_CARDINAL;
                v->size = sizeof(ContextAddress);
                v->value = alloc_str(v->size);
                v->remote = 0;
                if (get_symbol_address(&sym, expression_frame, (ContextAddress *)v->value) < 0) {
                    error(errno, "Cannot retrieve symbol address");
                }
                return;
            case SYM_CLASS_TYPE:
                error(ERR_INV_EXPRESSION, "Symbol is a type and has no value");
            default:
                error(ERR_UNSUPPORTED, "Invalid symbol class");
            }
        }
    }
#else
    error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
}

static void load_value(Value * v) {
    void * value;

    if (!v->remote) return;
    /*
    if (v->type_class == TYPE_CLASS_ARRAY) {
        v->size = sizeof(ContextAddress);
        v->value = alloc_str(v->size);
        memcpy(v->value, &v->address, v->size);
        v->remote = 0;
        v->address = 0;
        v->type_class = TYPE_CLASS_POINTER;
    }
    */
    value = alloc_str(v->size);
    if (context_read_mem(expression_context, v->address, value, v->size) < 0) {
        error(errno, "Can't read variable value");
    }
    check_breakpoints_on_memory_read(expression_context, v->address, value, v->size);
    v->value = value;
    v->remote = 0;
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

static int64 to_int(Value * v) {
    if (v == NULL) return 0;

    if (is_number(v)) {
        load_value(v);

        if (v->type_class == TYPE_CLASS_REAL) {
            switch (v->size)  {
            case 4: return (int64)*(float *)v->value;
            case 8: return (int64)*(double *)v->value;
            }
        }
        else if (v->type_class == TYPE_CLASS_CARDINAL) {
            switch (v->size)  {
            case 1: return (int64)*(unsigned char *)v->value;
            case 2: return (int64)*(unsigned short *)v->value;
            case 4: return (int64)*(unsigned long *)v->value;
            case 8: return (int64)*(uns64 *)v->value;
            }
        }
        else {
            switch (v->size)  {
            case 1: return *(signed char *)v->value;
            case 2: return *(short *)v->value;
            case 4: return *(long *)v->value;
            case 8: return *(int64 *)v->value;
            }
        }
    }

    error(ERR_INV_EXPRESSION, "Operation is not applicable for the value type");
    return 0;
}

static uns64 to_uns(Value * v) {
    if (v == NULL) return 0;

    if (is_number(v)) {
        load_value(v);

        if (v->type_class == TYPE_CLASS_REAL) {
            switch (v->size)  {
            case 4: return (uns64)*(float *)v->value;
            case 8: return (uns64)*(double *)v->value;
            }
        }
        else if (v->type_class == TYPE_CLASS_CARDINAL) {
            switch (v->size)  {
            case 1: return *(unsigned char *)v->value;
            case 2: return *(unsigned short *)v->value;
            case 4: return *(unsigned long *)v->value;
            case 8: return *(uns64 *)v->value;
            }
        }
        else {
            switch (v->size)  {
            case 1: return (uns64)*(signed char *)v->value;
            case 2: return (uns64)*(short *)v->value;
            case 4: return (uns64)*(long *)v->value;
            case 8: return (uns64)*(int64 *)v->value;
            }
        }
    }

    error(ERR_INV_EXPRESSION, "Operation is not applicable for the value type");
    return 0;
}

static double to_double(Value * v) {
    if (v == NULL) return 0;

    if (is_number(v)) {
        load_value(v);

        if (v->type_class == TYPE_CLASS_REAL) {
            switch (v->size)  {
            case 4: return *(float *)v->value;
            case 8: return *(double *)v->value;
            }
        }
        else if (v->type_class == TYPE_CLASS_CARDINAL) {
            switch (v->size)  {
            case 1: return (double)*(unsigned char *)v->value;
            case 2: return (double)*(unsigned short *)v->value;
            case 4: return (double)*(unsigned long *)v->value;
            case 8: return (double)*(uns64 *)v->value;
            }
        }
        else {
            switch (v->size)  {
            case 1: return (double)*(signed char *)v->value;
            case 2: return (double)*(short *)v->value;
            case 4: return (double)*(long *)v->value;
            case 8: return (double)*(int64 *)v->value;
            }
        }
    }

    error(ERR_INV_EXPRESSION, "Operation is not applicable for the value type");
    return 0;
}

static int to_boolean(Value * v) {
    if (v == NULL) return 0;
    return to_int(v) != 0;
}

static void expression(Value * v);

static void primary_expression(Value * v) {
    if (text_sy == '(') {
        next_sy();
        expression(v);
        if (text_sy != ')') error(ERR_INV_EXPRESSION, "Missing ')'");
        next_sy();
    }
    else if (text_sy == SY_VAL) {
        if (v) *v = text_val;
        next_sy();
    }
    else if (text_sy == SY_ID) {
        identifier((char *)text_val.value, v);
        next_sy();
    }
    else {
        error(ERR_INV_EXPRESSION, "Syntax error");
    }
}

static void op_deref(Value * v) {
#if SERVICE_Symbols
    if (v->type_class != TYPE_CLASS_ARRAY && v->type_class != TYPE_CLASS_POINTER) {
        error(ERR_INV_EXPRESSION, "Array or pointer type expected");
    }
    if (v->type_class == TYPE_CLASS_POINTER) {
        load_value(v);
        switch (v->size)  {
        case 2: v->address = (ContextAddress)*(unsigned short *)v->value; break;
        case 4: v->address = (ContextAddress)*(unsigned long *)v->value; break;
        case 8: v->address = (ContextAddress)*(uns64 *)v->value; break;
        default: error(ERR_INV_EXPRESSION, "Invalid value size");
        }
    }
    if (get_symbol_base_type(&v->type, &v->type) < 0) {
        error(errno, "Cannot retrieve symbol type");
    }
    if (get_symbol_type_class(&v->type, &v->type_class) < 0) {
        error(errno, "Cannot retrieve symbol type class");
    }
    if (get_symbol_size(&v->type, &v->size) < 0) {
        error(errno, "Cannot retrieve symbol size");
    }
    v->value = NULL;
    v->remote = 1;
#else
    error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
}

static void op_field(Value * v) {
    char * name = text_val.value;
    if (text_sy != SY_ID) {
        error(ERR_INV_EXPRESSION, "Field name expected");
    }
    next_sy();
    if (v->type_class != TYPE_CLASS_COMPOSITE) {
        error(ERR_INV_EXPRESSION, "Composite type expected");
    }
#if SERVICE_Symbols
    {
        Symbol sym;
        size_t size = 0;
        unsigned long offs = 0;
        Symbol * children = NULL;
        int count = 0;
        int i;

        if (get_symbol_children(&v->type, &children, &count) < 0) {
            error(errno, "Cannot retrieve field list");
        }
        for (i = 0; i < count; i++) {
            char * s = NULL;
            if (get_symbol_name(children + i, &s) < 0) {
                error(errno, "Cannot retrieve field name");
            }
            if (s == NULL) continue;
            if (strcmp(s, name) == 0) {
                loc_free(s);
                sym = children[i];
                break;
            }
            loc_free(s);
        }
        loc_free(children);
        if (i == count) {
            error(ERR_SYM_NOT_FOUND, "Symbol not found");
        }
        if (sym.sym_class != SYM_CLASS_REFERENCE) {
            error(ERR_UNSUPPORTED, "Invalid symbol class");
        }
        if (get_symbol_size(&sym, &size) < 0) {
            error(errno, "Cannot retrieve field size");
        }
        if (get_symbol_offset(&sym, &offs) < 0) {
            error(errno, "Cannot retrieve field offset");
        }
        if (offs + size > v->size) {
            error(errno, "Invalid field offset and/or size");
        }
        if (v->remote) {
            v->address += offs;
        }
        else {
            v->value = (char *)v->value + offs;
        }
        v->size = size;
        if (get_symbol_type(&sym, &v->type) < 0) {
            error(errno, "Cannot retrieve symbol type");
        }
        if (get_symbol_type_class(&sym, &v->type_class) < 0) {
            error(errno, "Cannot retrieve symbol type class");
        }
    }
#else
    error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
}

static void op_index(Value * v) {
#if SERVICE_Symbols
    Value i;
    unsigned offs = 0;
    size_t size = 0;
    Symbol type;

    if (v->type_class != TYPE_CLASS_ARRAY && v->type_class != TYPE_CLASS_POINTER) {
        error(ERR_INV_EXPRESSION, "Array or pointer expected");
    }
    if (v->type_class == TYPE_CLASS_POINTER) {
        load_value(v);
        switch (v->size)  {
        case 2: v->address = (ContextAddress)*(unsigned short *)v->value; break;
        case 4: v->address = (ContextAddress)*(unsigned long *)v->value; break;
        case 8: v->address = (ContextAddress)*(uns64 *)v->value; break;
        default: error(ERR_INV_EXPRESSION, "Invalid value size");
        }
    }
    if (get_symbol_base_type(&v->type, &type) < 0) {
        error(errno, "Cannot get array element type");
    }
    if (get_symbol_size(&type, &size) < 0) {
        error(errno, "Cannot get array element type");
    }
    expression(&i);
    /* TODO: array lowest bound */
    offs = (unsigned)to_uns(&i) * size;
    if (v->type_class == TYPE_CLASS_ARRAY && offs + size > v->size) {
        error(ERR_INV_EXPRESSION, "Invalid index");
    }
    if (v->remote) {
        v->address += offs;
    }
    else {
        v->value = (char *)v->value + offs;
    }
    v->size = size;
    v->type = type;
    if (get_symbol_type_class(&type, &v->type_class) < 0) {
        error(errno, "Cannot retrieve symbol type class");
    }
#else
    error(ERR_UNSUPPORTED, "Symbols service not available");
#endif
}

static void op_addr(Value * v) {
    if (!v->remote) error(ERR_INV_EXPRESSION, "Invalid '&': value has no address");
    v->size = sizeof(ContextAddress);
    v->value = alloc_str(text_val.size);
    v->remote = 0;
    *(ContextAddress *)v->value = v->address;
    v->address = 0;
    v->type_class = TYPE_CLASS_POINTER;
#if SERVICE_Symbols
    if (get_symbol_pointer(&v->type, &v->type)) {
        error(errno, "Cannot get pointer type");
    }
#else
    memset(&v->type, 0, sizeof(v->type));
#endif
}

static void postfix_expression(Value * v) {
    primary_expression(v);
    while (1) {
        if (text_sy == '.') {
            next_sy();
            op_field(v);
        }
        else if (text_sy == '[') {
            next_sy();
            op_index(v);
            if (text_sy != ']') {
                error(ERR_INV_EXPRESSION, "']' expected");
            }
            next_sy();
        }
        else if (text_sy == SY_REF) {
            next_sy();
            op_deref(v);
            op_field(v);
        }
        else {
            break;
        }
    }
}

static void unary_expression(Value * v) {
    switch (text_sy) {
    case '*':
        next_sy();
        unary_expression(v);
        op_deref(v);
        break;
    case '&':
        next_sy();
        unary_expression(v);
        op_addr(v);
        break;
    case '+':
        next_sy();
                unary_expression(v);
        if (!is_number(v)) {
            error(ERR_INV_EXPRESSION, "Numeric types expected");
        }
        break;
    case '-':
        next_sy();
        unary_expression(v);
        if (!is_number(v)) {
            error(ERR_INV_EXPRESSION, "Numeric types expected");
        }
        else if (v->type_class == TYPE_CLASS_REAL) {
            double * value = alloc_str(sizeof(double));
            *value = -to_double(v);
            v->type_class = TYPE_CLASS_REAL;
            v->size = sizeof(double);
            v->value = value;
        }
        else if (v->type_class != TYPE_CLASS_CARDINAL) {
            int64 * value = alloc_str(sizeof(int64));
            *value = -to_int(v);
            v->type_class = TYPE_CLASS_INTEGER;
            v->size = sizeof(int64);
            v->value = value;
        }
        break;
    case '!':
        next_sy();
        unary_expression(v);
        if (!is_whole_number(v)) {
            error(ERR_INV_EXPRESSION, "Integral types expected");
        }
        else {
            int * value = alloc_str(sizeof(int));
            *value = !to_int(v);
            v->type_class = TYPE_CLASS_INTEGER;
            v->size = sizeof(int);
            v->value = value;
        }
        break;
    case '~':
        next_sy();
                unary_expression(v);
        if (!is_whole_number(v)) {
            error(ERR_INV_EXPRESSION, "Integral types expected");
        }
        else {
            int64 * value = alloc_str(sizeof(int64));
            *value = ~to_int(v);
            v->size = sizeof(int64);
            v->value = value;
        }
        break;
    default:
        postfix_expression(v);
        break;
    }
}

static void cast_expression(Value * v) {
    /* TODO: cast_expression() */
    unary_expression(v);
}

static void multiplicative_expression(Value * v) {
    cast_expression(v);
    while (text_sy == '*' || text_sy == '/' || text_sy == '%') {
        Value x;
        int sy = text_sy;
        next_sy();
        cast_expression(v ? &x : NULL);
        if (v) {
            if (!is_number(v) || !is_number(&x)) {
                error(ERR_INV_EXPRESSION, "Numeric types expected");
            }
            if (sy != '*' && to_int(&x) == 0) {
                error(ERR_INV_EXPRESSION, "Dividing by zero");
            }
            if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                double * value = alloc_str(sizeof(double));
                switch (sy) {
                case '*': *value = to_double(v) * to_double(&x); break;
                case '/': *value = to_double(v) / to_double(&x); break;
                default: error(ERR_INV_EXPRESSION, "Invalid type");
                }
                v->type_class = TYPE_CLASS_REAL;
                v->size = sizeof(double);
                v->value = value;
            }
            else if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                uns64 * value = alloc_str(sizeof(uns64));
                switch (sy) {
                case '*': *value = to_uns(v) * to_uns(&x); break;
                case '/': *value = to_uns(v) / to_uns(&x); break;
                case '%': *value = to_uns(v) % to_uns(&x); break;
                }
                v->type_class = TYPE_CLASS_CARDINAL;
                v->size = sizeof(uns64);
                v->value = value;
            }
            else {
                int64 * value = alloc_str(sizeof(int64));
                switch (sy) {
                case '*': *value = to_int(v) * to_int(&x); break;
                case '/': *value = to_int(v) / to_int(&x); break;
                case '%': *value = to_int(v) % to_int(&x); break;
                }
                v->type_class = TYPE_CLASS_INTEGER;
                v->size = sizeof(int64);
                v->value = value;
            }
            v->remote = 0;
        }
    }
}

static void additive_expression(Value * v) {
    multiplicative_expression(v);
    while (text_sy == '+' || text_sy == '-') {
        Value x;
        int sy = text_sy;
        next_sy();
        multiplicative_expression(v ? &x : NULL);
        if (v) {
            if (sy == '+' && v->type_class == TYPE_CLASS_ARRAY && x.type_class == TYPE_CLASS_ARRAY) {
                char * value;
                load_value(v);
                load_value(&x);
                v->size = strlen((char *)v->value) + strlen((char *)x.value) + 1;
                value = alloc_str(v->size);
                strcpy(value, v->value);
                strcat(value, x.value);
                v->value = value;
            }
            else if (!is_number(v) || !is_number(&x)) {
                error(ERR_INV_EXPRESSION, "Numeric types expected");
            }
            else if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                double * value = alloc_str(sizeof(double));
                switch (sy) {
                case '+': *value = to_double(v) + to_double(&x); break;
                case '-': *value = to_double(v) - to_double(&x); break;
                }
                v->type_class = TYPE_CLASS_REAL;
                v->size = sizeof(double);
                v->value = value;
            }
            else if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                uns64 * value = alloc_str(sizeof(uns64));
                switch (sy) {
                case '+': *value = to_uns(v) + to_uns(&x); break;
                case '-': *value = to_uns(v) - to_uns(&x); break;
                }
                v->type_class = TYPE_CLASS_CARDINAL;
                v->size = sizeof(uns64);
                v->value = value;
            }
            else {
                int64 * value = alloc_str(sizeof(int64));
                switch (sy) {
                case '+': *value = to_int(v) + to_int(&x); break;
                case '-': *value = to_int(v) - to_int(&x); break;
                }
                v->type_class = TYPE_CLASS_INTEGER;
                v->size = sizeof(int64);
                v->value = value;
            }
            v->remote = 0;
        }
    }
}

static void shift_expression(Value * v) {
    additive_expression(v);
    while (text_sy == SY_SHL || text_sy == SY_SHR) {
        Value x;
        int sy = text_sy;
        next_sy();
        additive_expression(v ? &x : NULL);
        if (v) {
            uns64 * value = alloc_str(sizeof(uns64));
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            if (x.type_class != TYPE_CLASS_CARDINAL && to_int(&x) < 0) {
                if (v->type_class == TYPE_CLASS_CARDINAL) {
                    switch (sy) {
                    case SY_SHL: *value = to_uns(v) >> -to_int(&x); break;
                    case SY_SHR: *value = to_uns(v) << -to_int(&x); break;
                    }
                }
                else {
                    switch (sy) {
                    case SY_SHL: *value = to_int(v) >> -to_int(&x); break;
                    case SY_SHR: *value = to_int(v) << -to_int(&x); break;
                    }
                    v->type_class = TYPE_CLASS_INTEGER;
                }
            }
            else {
                if (v->type_class == TYPE_CLASS_CARDINAL) {
                    switch (sy) {
                    case SY_SHL: *value = to_uns(v) << to_uns(&x); break;
                    case SY_SHR: *value = to_uns(v) >> to_uns(&x); break;
                    }
                }
                else {
                    switch (sy) {
                    case SY_SHL: *value = to_int(v) << to_uns(&x); break;
                    case SY_SHR: *value = to_int(v) >> to_uns(&x); break;
                    }
                    v->type_class = TYPE_CLASS_INTEGER;
                }
            }
            v->value = value;
            v->size = sizeof(uns64);
            v->remote = 0;
        }
    }
}

static void relational_expression(Value * v) {
    shift_expression(v);
    while (text_sy == '<' || text_sy == '>' || text_sy == SY_LEQ || text_sy == SY_GEQ) {
        Value x;
        int sy = text_sy;
        next_sy();
        shift_expression(v ? &x : NULL);
        if (v) {
            int * value = alloc_str(sizeof(int));
            if (v->type_class == TYPE_CLASS_ARRAY && x.type_class == TYPE_CLASS_ARRAY) {
                int n = 0;
                load_value(v);
                load_value(&x);
                n = strcmp((char *)v->value, (char *)x.value);
                switch (sy) {
                case '<': *value = n < 0; break;
                case '>': *value = n > 0; break;
                case SY_LEQ: *value = n <= 0; break;
                case SY_GEQ: *value = n >= 0; break;
                }
            }
            else if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                switch (sy) {
                case '<': *value = to_double(v) < to_double(&x); break;
                case '>': *value = to_double(v) > to_double(&x); break;
                case SY_LEQ: *value = to_double(v) <= to_double(&x); break;
                case SY_GEQ: *value = to_double(v) >= to_double(&x); break;
                }
            }
            else if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                switch (sy) {
                case '<': *value = to_uns(v) < to_uns(&x); break;
                case '>': *value = to_uns(v) > to_uns(&x); break;
                case SY_LEQ: *value = to_uns(v) <= to_uns(&x); break;
                case SY_GEQ: *value = to_uns(v) >= to_uns(&x); break;
                }
            }
            else {
                switch (sy) {
                case '<': *value = to_int(v) < to_int(&x); break;
                case '>': *value = to_int(v) > to_int(&x); break;
                case SY_LEQ: *value = to_int(v) <= to_int(&x); break;
                case SY_GEQ: *value = to_int(v) >= to_int(&x); break;
                }
            }
            v->type_class = TYPE_CLASS_INTEGER;
            v->value = value;
            v->size = sizeof(int);
            v->remote = 0;
        }
    }
}

static void equality_expression(Value * v) {
    relational_expression(v);
    while (text_sy == SY_EQU || text_sy == SY_NEQ) {
        Value x;
        int sy = text_sy;
        next_sy();
        relational_expression(v ? &x : NULL);
        if (v) {
            int * value = alloc_str(sizeof(int));
            if (v->type_class == TYPE_CLASS_ARRAY && x.type_class == TYPE_CLASS_ARRAY) {
                load_value(v);
                load_value(&x);
                *value = strcmp((char *)v->value, (char *)x.value) == 0;
            }
            else if (v->type_class == TYPE_CLASS_REAL || x.type_class == TYPE_CLASS_REAL) {
                *value = to_double(v) == to_double(&x); break;
            }
            else {
                *value = to_int(v) == to_int(&x);
            }
            if (sy == SY_NEQ) *value = !*value;
            v->type_class = TYPE_CLASS_INTEGER;
            v->value = value;
            v->size = sizeof(int);
            v->remote = 0;
        }
    }
}

static void and_expression(Value * v) {
    equality_expression(v);
    while (text_sy == '&') {
        Value x;
        next_sy();
        equality_expression(v ? &x : NULL);
        if (v) {
            int64 * value = alloc_str(sizeof(int64));
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            *value = to_int(v) & to_int(&x);
            if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                v->type_class = TYPE_CLASS_CARDINAL;
            }
            else {
                v->type_class = TYPE_CLASS_INTEGER;
            }
            v->value = value;
            v->size = sizeof(int64);
            v->remote = 0;
        }
    }
}

static void exclusive_or_expression(Value * v) {
    and_expression(v);
    while (text_sy == '^') {
        Value x;
        next_sy();
        and_expression(v ? &x : NULL);
        if (v) {
            int64 * value = alloc_str(sizeof(int64));
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            *value = to_int(v) ^ to_int(&x);
            if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                v->type_class = TYPE_CLASS_CARDINAL;
            }
            else {
                v->type_class = TYPE_CLASS_INTEGER;
            }
            v->value = value;
            v->size = sizeof(int64);
            v->remote = 0;
        }
    }
}

static void inclusive_or_expression(Value * v) {
    exclusive_or_expression(v);
    while (text_sy == '|') {
        Value x;
        next_sy();
        exclusive_or_expression(v ? &x : NULL);
        if (v) {
            int64 * value = alloc_str(sizeof(int64));
            if (!is_whole_number(v) || !is_whole_number(&x)) {
                error(ERR_INV_EXPRESSION, "Integral types expected");
            }
            *value = to_int(v) | to_int(&x);
            if (v->type_class == TYPE_CLASS_CARDINAL || x.type_class == TYPE_CLASS_CARDINAL) {
                v->type_class = TYPE_CLASS_CARDINAL;
            }
            else {
                v->type_class = TYPE_CLASS_INTEGER;
            }
            v->value = value;
            v->size = sizeof(int64);
            v->remote = 0;
        }
    }
}

static void logical_and_expression(Value * v) {
    inclusive_or_expression(v);
    while (text_sy == SY_AND) {
        Value x;
        int b = to_boolean(v);
        next_sy();
        inclusive_or_expression(v && b ? &x : NULL);
        if (v && b) *v = x;
    }
}

static void logical_or_expression(Value * v) {
    logical_and_expression(v);
    while (text_sy == SY_OR) {
        Value x;
        int b = to_boolean(v);
        next_sy();
        logical_and_expression(v && !b ? &x : NULL);
        if (v && !b) *v = x;
    }
}

static void conditional_expression(Value * v) {
    logical_or_expression(v);
    if (text_sy == '?') {
        Value x;
        Value y;
        int b = to_boolean(v);
        next_sy();
        expression(v && b ? &x : NULL);
        if (text_sy != ':') error(ERR_INV_EXPRESSION, "Missing ':'");
        next_sy();
        conditional_expression(v && !b ? &y : NULL);
        if (v) *v = b ? x : y;
    }
}

static void expression(Value * v) {
    /* TODO: assignments in expressions */
    conditional_expression(v);
}

int evaluate_expression(Context * ctx, int frame, char * s, int load, Value * v) {
    Trap trap;

    expression_context = ctx;
    expression_frame = frame;
    if (set_trap(&trap)) {
        str_pool_cnt = 0;
        while (str_alloc_list != NULL) {
            StringValue * str = str_alloc_list;
            str_alloc_list = str->next;
            loc_free(str);
        }
        text = s;
        text_pos = 0;
        text_len = strlen(s) + 1;
        next_ch();
        next_sy();
        expression(v);
        if (text_sy != 0) error(ERR_INV_EXPRESSION, "Illegal characters at the end of expression");
        if (load) load_value(v);
        clear_trap(&trap);
        return 0;
    }
    return -1;
}

int value_to_boolean(Value * v) {
    /* TODO: error handling */
    int r = 0;
    Trap trap;
    if (set_trap(&trap)) {
        r = to_boolean(v);
        clear_trap(&trap);
    }
    return r;
}

ContextAddress value_to_address(Value * v) {
    /* TODO: error handling */
    ContextAddress r = 0;
    Trap trap;
    if (set_trap(&trap)) {
        r = (ContextAddress)to_uns(v);
        clear_trap(&trap);
    }
    return r;
}

#if SERVICE_Expressions

#include "json.h"
#include "context.h"
#include "stacktrace.h"
#include "breakpoints.h"
#include "symbols.h"

typedef struct Expression Expression;

struct Expression {
    LINK link_all;
    LINK link_id;
    char id[256];
    char parent[256];
    char language[256];
    Channel * channel;
    char * script;
};

#define link_all2exp(A)  ((Expression *)((char *)(A) - (int)&((Expression *)0)->link_all))
#define link_id2exp(A)   ((Expression *)((char *)(A) - (int)&((Expression *)0)->link_id))

#define ID2EXP_HASH_SIZE 1023

static LINK expressions;
static LINK id2exp[ID2EXP_HASH_SIZE];

#define MAX_SYM_NAME 1024
#define BUF_SIZE 256

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

static int expression_context_id(char * id, char * parent, Context ** ctx, int * frame, char * name, Expression ** expr) {
    int err = 0;
    Expression * e = NULL;

    if (id[0] == 'S') {
        char * s = id + 1;
        int i = 0;
        while (*s && i < MAX_SYM_NAME - 1) {
            char ch = *s++;
            if (ch == '.') {
                if (*s == '.') {
                    name[i++] = '.';
                    continue;
                }
                break;
            }
            name[i++] = ch;
        }
        name[i] = 0;
        strcpy(parent, s);
        *expr = NULL;
    }
    else if ((e = find_expression(id)) != NULL) {
        name[0] = 0;
        strcpy(parent, e->parent);
        *expr = e;
    }
    else {
        err = ERR_INV_CONTEXT;
    }
    if (!err) {
        if ((*ctx = id2ctx(parent)) != NULL) {
            *frame = STACK_TOP_FRAME;
        }
        else if (is_stack_frame_id(parent, ctx, frame)) {
            /* OK */
        }
        else {
            err = ERR_INV_CONTEXT;
        }
    }
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

static void write_context(OutputStream * out, char * id, char * parent, char * name, Expression * expr) {
    write_stream(out, '{');
    json_write_string(out, "ID");
    write_stream(out, ':');
    json_write_string(out, id);

    write_stream(out, ',');

    json_write_string(out, "ParentID");
    write_stream(out, ':');
    json_write_string(out, parent);

    if (expr || name) {
        write_stream(out, ',');

        json_write_string(out, "Expression");
        write_stream(out, ':');
        json_write_string(out, expr ? expr->script : name);
    }

    write_stream(out, '}');
}

static void command_get_context(char * token, Channel * c) {
    int err = 0;
    char id[256];
    char parent[256];
    char name[MAX_SYM_NAME];
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Expression * expr = NULL;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    if (expression_context_id(id, parent, &ctx, &frame, name, &expr) < 0) err = errno;

    if (!err && expr == NULL) {
#if SERVICE_Symbols
        Symbol sym;
        if (find_symbol(ctx, frame, name, &sym) < 0) err = errno;
#else
        err = ERR_INV_CONTEXT;
#endif
    }

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, err);

    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        write_context(&c->out, id, parent, name, expr);
        write_stream(&c->out, 0);
    }

    write_stream(&c->out, MARKER_EOM);
}

#if SERVICE_Symbols

typedef struct GetChildrenContext {
    Channel * channel;
    char id[256];
    int cnt;
} GetChildrenContext;

static void get_children_callback(void * x, char * name, Symbol * symbol) {
    GetChildrenContext * args = (GetChildrenContext *)x;
    Channel * c = args->channel;
    char * s;

    if (args->cnt == 0) {
        write_errno(&c->out, 0);
        write_stream(&c->out, '[');
    }
    else {
        write_stream(&c->out, ',');
    }
    write_stream(&c->out, '"');
    write_stream(&c->out, 'S');
    s = name;
    while (*s) {
        if (*s == '.') write_stream(&c->out, '.');
        json_write_char(&c->out, *s++);
    }
    write_stream(&c->out, '.');
    s = args->id;
    while (*s) json_write_char(&c->out, *s++);
    write_stream(&c->out, '"');
    args->cnt++;
}

#endif

static void command_get_children(char * token, Channel * c) {
    char id[256];

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);

    /* TODO: Expressions.getChildren - structures */
#if SERVICE_Symbols
    {
        Context * ctx;
        int frame = STACK_NO_FRAME;
        GetChildrenContext args;
        int err = 0;

        args.cnt = 0;
        args.channel = c;
        strncpy(args.id, id, sizeof(args.id));

        if ((ctx = id2ctx(id)) != NULL) {
            if (context_has_state(ctx)) {
                char * frame_id = get_stack_frame_id(ctx, STACK_TOP_FRAME);
                if (frame_id == NULL) {
                    err = errno;
                }
                else {
                    frame = STACK_TOP_FRAME;
                    strncpy(args.id, frame_id, sizeof(args.id));
                }
            }
        }
        else if (is_stack_frame_id(id, &ctx, &frame)) {
            /* OK */
        }
        else {
            ctx = NULL;
        }

        if (ctx != NULL && err == 0 && enumerate_symbols(
                ctx, frame, get_children_callback, &args) < 0) err = errno;

        if (args.cnt == 0) {
            write_errno(&c->out, err);
            write_stream(&c->out, '[');
        }
    }
#else
    write_errno(&c->out, ERR_UNSUPPORTED);
    write_stream(&c->out, '[');
#endif
    write_stream(&c->out, ']');
    write_stream(&c->out, 0);

    write_stream(&c->out, MARKER_EOM);
}

static void command_create(char * token, Channel * c) {
    char parent[256];
    char language[256];
    char * script;
    int err = 0;
    Expression * e;

    json_read_string(&c->inp, parent, sizeof(parent));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    json_read_string(&c->inp, language, sizeof(language));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    script = json_read_alloc_string(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    e = (Expression *)loc_alloc_zero(sizeof(Expression));
    do snprintf(e->id, sizeof(e->id), "EXPR%d", expr_id_cnt++);
    while (find_expression(e->id) != NULL);
    strncpy(e->parent, parent, sizeof(e->parent));
    strncpy(e->language, language, sizeof(e->language));
    e->channel = c;
    e->script = script;
    list_add_last(&e->link_all, &expressions);
    list_add_last(&e->link_id, id2exp + expression_hash(e->id));

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, err);

    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        write_context(&c->out, e->id, parent, NULL, e);
        write_stream(&c->out, 0);
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_evaluate(char * token, Channel * c) {
    int err = 0;
    char id[256];
    char parent[256];
    char name[MAX_SYM_NAME];
    Context * ctx;
    int frame;
    Expression * expr = NULL;
    Value value;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    if (expression_context_id(id, parent, &ctx, &frame, name, &expr) < 0) err = errno;
    if (!err && evaluate_expression(ctx, frame, expr ? expr->script : name, 1, &value) < 0) err = errno;

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        JsonWriteBinaryState state;

        assert(!value.remote);
        json_write_binary_start(&state, &c->out);
        json_write_binary_data(&state, value.value, value.size);
        json_write_binary_end(&state);
        write_stream(&c->out, 0);
    }
    write_errno(&c->out, err);
    if (err) {
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

        if (value.type.ctx != NULL) {
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, "Type");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(&value.type));
            cnt++;
        }

        write_stream(&c->out, '}');
        write_stream(&c->out, 0);
    }
    write_stream(&c->out, MARKER_EOM);
}

static void command_assign(char * token, Channel * c) {
    char id[256];
    int err = 0;
    char parent[256];
    char name[MAX_SYM_NAME];
    Context * ctx;
    int frame;
    Expression * expr = NULL;
    Value value;
    JsonReadBinaryState state;
    char buf[BUF_SIZE];
    unsigned long size = 0;
    ContextAddress addr;
    ContextAddress addr0;
    unsigned long size0;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);

    if (expression_context_id(id, parent, &ctx, &frame, name, &expr) < 0) err = errno;
    if (!err && evaluate_expression(ctx, frame, expr ? expr->script : name, 0, &value) < 0) err = errno;

    addr0 = value.address;
    size0 = value.size;
    addr = addr0;

    json_read_binary_start(&state, &c->inp);
    for (;;) {
        int rd = json_read_binary_data(&state, buf, sizeof(buf));
        if (rd == 0) break;
        if (err == 0) {
            if (value.remote) {
                check_breakpoints_on_memory_write(ctx, addr, buf, rd);
                if (context_write_mem(ctx, addr, buf, rd) < 0) {
                    err = errno;
                }
                else {
                    addr += rd;
                }
            }
            else {
                err = ERR_UNSUPPORTED;
            }
        }
        size += rd;
    }
    json_read_binary_end(&state);

    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_errno(&c->out, errno);
    write_stream(&c->out, MARKER_EOM);
}

static void command_dispose(char * token, Channel * c) {
    char id[256];
    int err = 0;
    Expression * e;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

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

void ini_expressions_service(Protocol * proto) {
    unsigned i;
#ifndef  NDEBUG
    Value v;
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "0", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int64) && *(int *)v.value == 0);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "0.", 1, &v) != 0);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "2 * 2", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int64) && *(int64 *)v.value == 4);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "1 ? 2 : 3", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int64) && *(int64 *)v.value == 2);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "0 ? 2 : 3", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int64) && *(int64 *)v.value == 3);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "(1?2:3) == 2 && (0?2:3) == 3", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int) && *(int *)v.value == 1);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "(1?2:3) != 2 || (0?2:3) != 3", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int) && *(int *)v.value == 0);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "5>2 && 4<6", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int) && *(int *)v.value == 1);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "5<=2 || 4>=6", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int) && *(int *)v.value == 0);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "((5*2+7-1)/2)>>1==4 && 1<<3==8 && 5%2==1", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int) && *(int *)v.value == 1);
    assert(evaluate_expression(NULL, STACK_NO_FRAME, "\042ABC\042 + \042DEF\042 == \042ABCDEF\042", 1, &v) == 0);
    assert(v.type_class == TYPE_CLASS_INTEGER && v.size == sizeof(int) && *(int *)v.value == 1);
#endif
    list_init(&expressions);
    for (i = 0; i < ID2EXP_HASH_SIZE; i++) list_init(id2exp + i);
    add_channel_close_listener(on_channel_close);
    add_command_handler(proto, EXPRESSIONS, "getContext", command_get_context);
    add_command_handler(proto, EXPRESSIONS, "getChildren", command_get_children);
    add_command_handler(proto, EXPRESSIONS, "create", command_create);
    add_command_handler(proto, EXPRESSIONS, "evaluate", command_evaluate);
    add_command_handler(proto, EXPRESSIONS, "assign", command_assign);
    add_command_handler(proto, EXPRESSIONS, "dispose", command_dispose);
}

#endif
