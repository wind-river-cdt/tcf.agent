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


#include <tcf/config.h>

#if SERVICE_Symbols

#include <assert.h>
#include <tcf/framework/channel.h>
#include <tcf/framework/json.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/cache.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/memorymap.h>
#include <tcf/services/symbols.h>
#include <tcf/services/vm.h>

static const char * SYMBOLS = "Symbols";

static Symbol ** list_buf = NULL;
static unsigned list_cnt = 0;
static unsigned list_max = 0;

static void list_add(Symbol * sym) {
    if (list_cnt >= list_max) {
        list_max = list_max == 0 ? 32 : list_max * 2;
        list_buf = (Symbol **)loc_realloc(list_buf, sizeof(Symbol *) * list_max);
    }
    list_buf[list_cnt++] = sym;
}

static LocationExpressionState * evaluate_symbol_location(const Symbol * sym, unsigned args_cnt) {
    Trap trap;
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    LocationInfo * loc_info = NULL;
    StackFrame * frame_info = NULL;
    LocationExpressionState * state = NULL;
    static uint64_t args[] = { 0, 0 };

    if (get_symbol_frame(sym, &ctx, &frame) < 0) return NULL;
    if (get_location_info(sym, &loc_info) < 0) return NULL;
    if (loc_info->args_cnt != args_cnt) {
        set_errno(ERR_OTHER, "Wrong object kind");
        return NULL;
    }
    if (frame != STACK_NO_FRAME && get_frame_info(ctx, frame, &frame_info) < 0) return NULL;
    if (!set_trap(&trap)) return NULL;
    state = evaluate_location_expression(ctx, frame_info,
        loc_info->value_cmds.cmds, loc_info->value_cmds.cnt, args, args_cnt);
    clear_trap(&trap);
    return state;
}

int get_symbol_address(const Symbol * sym, ContextAddress * address) {
    LocationExpressionState * state = evaluate_symbol_location(sym, 0);
    if (state == NULL) return -1;
    if (state->stk_pos == 1) {
        *address = (ContextAddress)state->stk[0];
        return 0;
    }
    set_errno(ERR_OTHER, "Symbol does not have a memory address");
    return -1;
}

int get_symbol_register(const Symbol * sym, Context ** ctx, int * frame, RegisterDefinition ** reg) {
    LocationExpressionState * state = evaluate_symbol_location(sym, 0);
    if (state == NULL) return -1;
    if (state->pieces_cnt == 1 && state->pieces->reg != NULL && state->pieces->reg->size == state->pieces->size) {
        if (get_symbol_frame(sym, ctx, frame) < 0) return -1;
        *reg = state->pieces->reg;
        return 0;
    }
    set_errno(ERR_OTHER, "Symbol is not located in a register");
    return -1;
}

int get_symbol_offset(const Symbol * sym, ContextAddress * offset) {
    LocationExpressionState * state = evaluate_symbol_location(sym, 1);
    if (state == NULL) return -1;
    if (state->pieces_cnt > 0) {
        set_errno(ERR_OTHER, "Cannot get member offset: the symbol is a bit field");
        return -1;
    }
    if (state->stk_pos == 1) {
        *offset = (ContextAddress)state->stk[0];
        return 0;
    }
    set_errno(ERR_OTHER, "Symbol does not have a member offset");
    return -1;
}

typedef struct CommandGetContextArgs {
    char token[256];
    char id[256];
} CommandGetContextArgs;

static void command_get_context_cache_client(void * x) {
    CommandGetContextArgs * args = (CommandGetContextArgs *)x;
    Channel * c = cache_channel();
    int err = 0;
    Symbol * sym = NULL;
    char * owner = NULL;
    char * name = NULL;
    int update_policy = 0;
    int sym_class = SYM_CLASS_UNKNOWN;
    int type_class = TYPE_CLASS_UNKNOWN;
    Symbol * type = NULL;
    Symbol * base = NULL;
    Symbol * index = NULL;
    Symbol * container = NULL;
    int has_size = 0;
    int has_length = 0;
    int has_lower_bound = 0;
    int has_offset = 0;
    int has_address = 0;
    int big_endian = 0;
    ContextAddress size = 0;
    ContextAddress length = 0;
    int64_t lower_bound = 0;
    ContextAddress offset = 0;
    ContextAddress address = 0;
    RegisterDefinition * reg = NULL;
    Context * reg_ctx = NULL;
    int reg_frame = 0;
    SYM_FLAGS flags = 0;
    void * value = NULL;
    size_t value_size = 0;
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;

    if (id2symbol(args->id, &sym) < 0) err = errno;

    if (err == 0) {
        get_symbol_class(sym, &sym_class);
        get_symbol_update_policy(sym, &owner, &update_policy);
        get_symbol_name(sym, &name);
        get_symbol_type_class(sym, &type_class);
        get_symbol_type(sym, &type);
        get_symbol_base_type(sym, &base);
        get_symbol_index_type(sym, &index);
        get_symbol_container(sym, &container);
        has_size = get_symbol_size(sym, &size) == 0;
        has_length = get_symbol_length(sym, &length) == 0;
        if (has_length) {
            has_lower_bound = get_symbol_lower_bound(sym, &lower_bound) == 0;
        }
        if (sym_class == SYM_CLASS_REFERENCE) {
            has_offset = get_symbol_offset(sym, &offset) == 0;
        }
        if (sym_class == SYM_CLASS_REFERENCE || sym_class == SYM_CLASS_FUNCTION) {
            LocationExpressionState * state = evaluate_symbol_location(sym, 0);
            if (state != NULL) {
                if (state->stk_pos == 1) {
                    address = (ContextAddress)state->stk[0];
                    has_address = 1;
                }
                if (state->pieces_cnt == 1 && state->pieces->reg != NULL &&
                        state->pieces->reg->size == state->pieces->size) {
                    reg = state->pieces->reg;
                }
            }
        }
        if (sym_class == SYM_CLASS_VALUE) {
            get_symbol_value(sym, &value, &value_size, &big_endian);
        }
        if (sym_class == SYM_CLASS_REFERENCE && !has_address && !has_offset) {
            get_symbol_value(sym, &value, &value_size, &big_endian);
            assert(value == NULL || update_policy == UPDATE_ON_EXE_STATE_CHANGES);
        }
        get_symbol_flags(sym, &flags);
        get_symbol_frame(sym, &ctx, &frame);
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (err == 0) {

        write_stream(&c->out, '{');

        json_write_string(&c->out, "ID");
        write_stream(&c->out, ':');
        json_write_string(&c->out, args->id);
        write_stream(&c->out, ',');

        if (owner != NULL) {
            json_write_string(&c->out, "OwnerID");
            write_stream(&c->out, ':');
            json_write_string(&c->out, owner);
            write_stream(&c->out, ',');

            json_write_string(&c->out, "UpdatePolicy");
            write_stream(&c->out, ':');
            json_write_long(&c->out, update_policy);
            write_stream(&c->out, ',');
        }

        if (name != NULL) {
            json_write_string(&c->out, "Name");
            write_stream(&c->out, ':');
            json_write_string(&c->out, name);
            write_stream(&c->out, ',');
        }

        if (type_class != TYPE_CLASS_UNKNOWN) {
            json_write_string(&c->out, "TypeClass");
            write_stream(&c->out, ':');
            json_write_long(&c->out, type_class);
            write_stream(&c->out, ',');
        }

        if (type != NULL) {
            json_write_string(&c->out, "TypeID");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(type));
            write_stream(&c->out, ',');
        }

        if (base != NULL) {
            json_write_string(&c->out, "BaseTypeID");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(base));
            write_stream(&c->out, ',');
        }

        if (index != NULL) {
            json_write_string(&c->out, "IndexTypeID");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(index));
            write_stream(&c->out, ',');
        }

        if (container != NULL) {
            json_write_string(&c->out, "ContainerID");
            write_stream(&c->out, ':');
            json_write_string(&c->out, symbol2id(container));
            write_stream(&c->out, ',');
        }

        if (has_size) {
            json_write_string(&c->out, "Size");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, size);
            write_stream(&c->out, ',');
        }

        if (has_length) {
            json_write_string(&c->out, "Length");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, length);
            write_stream(&c->out, ',');

            if (has_lower_bound) {
                json_write_string(&c->out, "LowerBound");
                write_stream(&c->out, ':');
                json_write_int64(&c->out, lower_bound);
                write_stream(&c->out, ',');

                json_write_string(&c->out, "UpperBound");
                write_stream(&c->out, ':');
                json_write_int64(&c->out, lower_bound + (int64_t)length - 1);
                write_stream(&c->out, ',');
            }
        }

        if (has_offset) {
            json_write_string(&c->out, "Offset");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, offset);
            write_stream(&c->out, ',');
        }

        if (has_address) {
            json_write_string(&c->out, "Address");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, address);
            write_stream(&c->out, ',');
        }

        if (reg != NULL) {
            json_write_string(&c->out, "Register");
            write_stream(&c->out, ':');
            json_write_string(&c->out, register2id(reg_ctx, reg_frame, reg));
            write_stream(&c->out, ',');
        }

        if (flags) {
            json_write_string(&c->out, "Flags");
            write_stream(&c->out, ':');
            json_write_long(&c->out, flags);
            write_stream(&c->out, ',');
        }

        if (value != NULL) {
            json_write_string(&c->out, "Value");
            write_stream(&c->out, ':');
            json_write_binary(&c->out, value, value_size);
            write_stream(&c->out, ',');

            if (big_endian) {
                json_write_string(&c->out, "BigEndian");
                write_stream(&c->out, ':');
                json_write_boolean(&c->out, 1);
                write_stream(&c->out, ',');
            }
        }

        if (frame != STACK_NO_FRAME) {
            json_write_string(&c->out, "Frame");
            write_stream(&c->out, ':');
            json_write_long(&c->out, frame);
            write_stream(&c->out, ',');
        }

        json_write_string(&c->out, "Class");
        write_stream(&c->out, ':');
        json_write_long(&c->out, sym_class);

        write_stream(&c->out, '}');
        write_stream(&c->out, 0);
    }
    else {
        write_stringz(&c->out, "null");
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_get_context(char * token, Channel * c) {
    CommandGetContextArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_get_context_cache_client, c, &args, sizeof(args));
}

typedef struct CommandGetChildrenArgs {
    char token[256];
    char id[256];
} CommandGetChildrenArgs;

static void command_get_children_cache_client(void * x) {
    CommandGetChildrenArgs * args = (CommandGetChildrenArgs *)x;
    Channel * c = cache_channel();
    int err = 0;
    Symbol * sym = NULL;
    Symbol ** list = NULL;
    int cnt = 0;

    if (id2symbol(args->id, &sym) < 0) err = errno;
    if (err == 0 && get_symbol_children(sym, &list, &cnt) < 0) err = errno;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (err == 0) {
        int i;
        write_stream(&c->out, '[');
        for (i = 0; i < cnt; i++) {
            if (i > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, symbol2id(list[i]));
        }
        write_stream(&c->out, ']');
        write_stream(&c->out, 0);
    }
    else {
        write_stringz(&c->out, "null");
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_get_children(char * token, Channel * c) {
    CommandGetChildrenArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_get_children_cache_client, c, &args, sizeof(args));
}

static void write_symbol_list(OutputStream * out) {
    if (list_cnt == 0) {
        write_stringz(out, "null");
    }
    else if (list_cnt == 1) {
        json_write_string(out, symbol2id(list_buf[0]));
        write_stream(out, 0);
    }
    else {
        unsigned i = 0;
        write_stream(out, '[');
        for (i = 0; i < list_cnt; i++) {
            if (i > 0) write_stream(out, ',');
            json_write_string(out, symbol2id(list_buf[i]));
        }
        write_stream(out, ']');
        write_stream(out, 0);
    }
}

typedef struct CommandFindByNameArgs {
    char token[256];
    char id[256];
    int find_first;
    ContextAddress ip;
    char * name;
} CommandFindByNameArgs;

static void command_find_by_name_cache_client(void * x) {
    CommandFindByNameArgs * args = (CommandFindByNameArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Symbol * sym = NULL;
    int err = 0;

    if (id2frame(args->id, &ctx, &frame) < 0) ctx = id2ctx(args->id);
    if (ctx == NULL) err = set_errno(ERR_INV_CONTEXT, args->id);
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    if (err == 0 && find_symbol_by_name(ctx, frame, args->ip, args->name, &sym) < 0) err = errno;

    list_cnt = 0;
    if (err == 0) {
        list_add(sym);
        if (!args->find_first) {
            while (find_next_symbol(&sym) == 0) list_add(sym);
            if (get_error_code(errno) != ERR_SYM_NOT_FOUND) err = errno;
        }
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);
    write_symbol_list(&c->out);
    write_stream(&c->out, MARKER_EOM);
    loc_free(args->name);
}

static void command_find_by_name_args(char * token, Channel * c, CommandFindByNameArgs * args) {
    args->ip = 0;
    json_read_string(&c->inp, args->id, sizeof(args->id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (peek_stream(&c->inp) != '"' && peek_stream(&c->inp) != 'n') {
        args->ip = (ContextAddress)json_read_uint64(&c->inp);
        if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    }
    args->name = json_read_alloc_string(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args->token, token, sizeof(args->token));
    cache_enter(command_find_by_name_cache_client, c, args, sizeof(CommandFindByNameArgs));
}

static void command_find_first(char * token, Channel * c) {
    CommandFindByNameArgs args;
    args.find_first = 1;
    command_find_by_name_args(token, c, &args);
}

static void command_find_by_name(char * token, Channel * c) {
    CommandFindByNameArgs args;
    args.find_first = 0;
    command_find_by_name_args(token, c, &args);
}

typedef struct CommandFindByAddrArgs {
    char token[256];
    char id[256];
    ContextAddress addr;
} CommandFindByAddrArgs;

static void command_find_by_addr_cache_client(void * x) {
    CommandFindByAddrArgs * args = (CommandFindByAddrArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Symbol * sym = NULL;
    int err = 0;

    if (id2frame(args->id, &ctx, &frame) < 0) ctx = id2ctx(args->id);
    if (ctx == NULL) err = set_errno(ERR_INV_CONTEXT, args->id);
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    if (err == 0 && find_symbol_by_addr(ctx, frame, args->addr, &sym) < 0) err = errno;

    list_cnt = 0;
    if (err == 0) {
        list_add(sym);
        while (find_next_symbol(&sym) == 0) list_add(sym);
        if (get_error_code(errno) != ERR_SYM_NOT_FOUND) err = errno;
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);
    write_symbol_list(&c->out);
    write_stream(&c->out, MARKER_EOM);
}

static void command_find_by_addr(char * token, Channel * c) {
    CommandFindByAddrArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args.addr = (ContextAddress)json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_find_by_addr_cache_client, c, &args, sizeof(args));
}

typedef struct CommandFindInScopeArgs {
    char token[256];
    char frame_id[256];
    char scope_id[256];
    ContextAddress ip;
    char * name;
} CommandFindInScopeArgs;

static void command_find_in_scope_cache_client(void * x) {
    CommandFindInScopeArgs * args = (CommandFindInScopeArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Symbol * scope = NULL;
    Symbol * sym = NULL;
    int err = 0;

    if (id2frame(args->frame_id, &ctx, &frame) < 0) ctx = id2ctx(args->frame_id);
    if (ctx == NULL) err = set_errno(ERR_INV_CONTEXT, args->frame_id);
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    if (err == 0 && args->scope_id[0] && id2symbol(args->scope_id, &scope) < 0) err = errno;
    if (err == 0 && find_symbol_in_scope(ctx, frame, args->ip, scope, args->name, &sym) < 0) err = errno;

    list_cnt = 0;
    if (err == 0) {
        list_add(sym);
        while (find_next_symbol(&sym) == 0) list_add(sym);
        if (get_error_code(errno) != ERR_SYM_NOT_FOUND) err = errno;
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);
    write_symbol_list(&c->out);
    write_stream(&c->out, MARKER_EOM);
    loc_free(args->name);
}

static void command_find_in_scope(char * token, Channel * c) {
    CommandFindInScopeArgs args;

    json_read_string(&c->inp, args.frame_id, sizeof(args.frame_id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args.ip = (ContextAddress)json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    json_read_string(&c->inp, args.scope_id, sizeof(args.scope_id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args.name = json_read_alloc_string(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_find_in_scope_cache_client, c, &args, sizeof(args));
}

typedef struct CommandListArgs {
    char token[256];
    char id[256];
} CommandListArgs;

static void list_callback(void * x, Symbol * sym) {
    list_add(sym);
}

static void command_list_cache_client(void * x) {
    CommandListArgs * args = (CommandListArgs *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    int err = 0;

    list_cnt = 0;

    if (id2frame(args->id, &ctx, &frame) < 0) ctx = id2ctx(args->id);
    if (ctx == NULL) err = set_errno(ERR_INV_CONTEXT, args->id);
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    if (err == 0 && enumerate_symbols(ctx, frame, list_callback, NULL) < 0) err = errno;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (err == 0) {
        unsigned i = 0;
        write_stream(&c->out, '[');
        for (i = 0; i < list_cnt; i++) {
            if (i > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, symbol2id(list_buf[i]));
        }
        write_stream(&c->out, ']');
        write_stream(&c->out, 0);
    }
    else {
        write_stringz(&c->out, "null");
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_list(char * token, Channel * c) {
    CommandListArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_list_cache_client, c, &args, sizeof(args));
}

typedef struct CommandGetArrayTypeArgs {
    char token[256];
    char id[256];
    uint64_t length;
} CommandGetArrayTypeArgs;

static void command_get_array_type_cache_client(void * x) {
    CommandGetArrayTypeArgs * args = (CommandGetArrayTypeArgs *)x;
    Channel * c = cache_channel();
    Symbol * sym = NULL;
    Symbol * arr = NULL;
    int err = 0;

    if (id2symbol(args->id, &sym) < 0) err = errno;
    if (err == 0 && get_array_symbol(sym, (ContextAddress)args->length, &arr) < 0) err = errno;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (err == 0) {
        json_write_string(&c->out, symbol2id(arr));
        write_stream(&c->out, 0);
    }
    else {
        write_stringz(&c->out, "null");
    }

    write_stream(&c->out, MARKER_EOM);
}

static void command_get_array_type(char * token, Channel * c) {
    CommandGetArrayTypeArgs args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args.length = json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_get_array_type_cache_client, c, &args, sizeof(args));
}

static void write_commands(OutputStream * out, Context * ctx, LocationExpressionCommand * cmds, unsigned cnt) {
    if (cmds != NULL) {
        unsigned i;
        write_stream(out, '[');
        for (i = 0; i < cnt; i++) {
            LocationExpressionCommand * cmd = cmds + i;
            if (i > 0) write_stream(out, ',');
            json_write_long(out, cmd->cmd);
            switch (cmd->cmd) {
            case SFT_CMD_NUMBER:
                write_stream(out, ',');
                json_write_int64(out, cmd->args.num);
                break;
            case SFT_CMD_ARG:
                write_stream(out, ',');
                json_write_ulong(out, cmd->args.arg_no);
                break;
            case SFT_CMD_RD_REG:
            case SFT_CMD_WR_REG:
                write_stream(out, ',');
                json_write_string(out, register2id(ctx, STACK_NO_FRAME, cmd->args.reg));
                break;
            case SFT_CMD_RD_MEM:
            case SFT_CMD_WR_MEM:
                write_stream(out, ',');
                json_write_ulong(out, cmd->args.mem.size);
                write_stream(out, ',');
                json_write_boolean(out, cmd->args.mem.big_endian);
                break;
            case SFT_CMD_LOCATION:
                write_stream(out, ',');
                json_write_binary(out, cmd->args.loc.code_addr, cmd->args.loc.code_size);
                write_stream(out, ',');
                write_stream(out, '{');
                json_write_string(out, "Machine");
                write_stream(out, ':');
                json_write_long(out, cmd->args.loc.reg_id_scope.machine);
                write_stream(out, ',');
                if (cmd->args.loc.reg_id_scope.os_abi) {
                    json_write_string(out, "ABI");
                    write_stream(out, ':');
                    json_write_long(out, cmd->args.loc.reg_id_scope.os_abi);
                    write_stream(out, ',');
                }
                if (cmd->args.loc.reg_id_scope.fp_abi) {
                    json_write_string(out, "FPABI");
                    write_stream(out, ':');
                    json_write_long(out, cmd->args.loc.reg_id_scope.fp_abi);
                    write_stream(out, ',');
                }
                json_write_string(out, "ELF64");
                write_stream(out, ':');
                json_write_boolean(out, cmd->args.loc.reg_id_scope.elf64);
                write_stream(out, ',');
                json_write_string(out, "RegIdType");
                write_stream(out, ':');
                json_write_long(out, cmd->args.loc.reg_id_scope.id_type);
                write_stream(out, ',');
                json_write_string(out, "AddrSize");
                write_stream(out, ':');
                json_write_long(out, cmd->args.loc.addr_size);
                write_stream(out, ',');
                json_write_string(out, "BigEndian");
                write_stream(out, ':');
                json_write_boolean(out, cmd->args.loc.reg_id_scope.big_endian);
                write_stream(out, '}');
                break;
            case SFT_CMD_PIECE:
                write_stream(out, ',');
                json_write_ulong(out, cmd->args.piece.bit_offs);
                write_stream(out, ',');
                json_write_ulong(out, cmd->args.piece.bit_size);
                write_stream(out, ',');
                if (cmd->args.piece.reg == NULL) write_string(out, "null");
                else json_write_string(out, register2id(ctx, STACK_NO_FRAME, cmd->args.piece.reg));
                write_stream(out, ',');
                if (cmd->args.piece.value != NULL) write_string(out, "null");
                else json_write_binary(out, cmd->args.piece.value, (cmd->args.piece.bit_size + 7) / 8);
                break;
            }
        }
        write_stream(out, ']');
    }
    else {
        write_string(out, "null");
    }
}

typedef struct CommandGetLocationInfo {
    char token[256];
    char id[256];
} CommandGetLocationInfo;

static void command_get_location_info_cache_client(void * x) {
    CommandGetLocationInfo * args = (CommandGetLocationInfo *)x;
    Channel * c = cache_channel();
    LocationInfo * info = NULL;
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    Symbol * sym = NULL;
    int err = 0;

    if (id2symbol(args->id, &sym) < 0) err = errno;
    else if (get_location_info(sym, &info) < 0) err = errno;
    else if (get_symbol_frame(sym, &ctx, &frame) < 0) err = errno;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    if (info == NULL) {
        write_stringz(&c->out, "null");
        write_stringz(&c->out, "null");
    }
    else {
        write_stream(&c->out, '{');
        json_write_string(&c->out, "ValueCmds");
        write_stream(&c->out, ':');
        write_commands(&c->out, ctx, info->value_cmds.cmds, info->value_cmds.cnt);
        if (info->length_cmds.cnt > 0) {
            write_stream(&c->out, ',');
            json_write_string(&c->out, "LengthCmds");
            write_stream(&c->out, ':');
            write_commands(&c->out, ctx, info->length_cmds.cmds, info->length_cmds.cnt);
            if (info->length_size > 0) {
                write_stream(&c->out, ',');
                json_write_string(&c->out, "LengthSize");
                write_stream(&c->out, ':');
                json_write_uint64(&c->out, info->length_size);
            }
            if (info->length_bits > 0) {
                write_stream(&c->out, ',');
                json_write_string(&c->out, "LengthBits");
                write_stream(&c->out, ':');
                json_write_ulong(&c->out, info->length_bits);
            }
        }
        if (info->args_cnt) {
            write_stream(&c->out, ',');
            json_write_string(&c->out, "ArgCnt");
            write_stream(&c->out, ':');
            json_write_ulong(&c->out, info->args_cnt);
        }
        if (info->code_size) {
            write_stream(&c->out, ',');
            json_write_string(&c->out, "CodeAddr");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, info->code_addr);
            write_stream(&c->out, ',');
            json_write_string(&c->out, "CodeSize");
            write_stream(&c->out, ':');
            json_write_uint64(&c->out, info->code_size);
        }
        write_stream(&c->out, '}');
        write_stream(&c->out, 0);
    }
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_location_info(char * token, Channel * c) {
    CommandGetLocationInfo args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_get_location_info_cache_client, c, &args, sizeof(args));
}

typedef struct CommandFindFrameInfo {
    char token[256];
    char id[256];
    ContextAddress addr;
} CommandFindFrameInfo;

static void command_find_frame_info_cache_client(void * x) {
    CommandFindFrameInfo * args = (CommandFindFrameInfo *)x;
    Channel * c = cache_channel();
    Context * ctx = NULL;
    StackTracingInfo * info = NULL;
    int err = 0;

    ctx = id2ctx(args->id);
    if (ctx == NULL) err = ERR_INV_CONTEXT;
    else if (get_stack_tracing_info(ctx, args->addr, &info) < 0) err = errno;

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);

    json_write_uint64(&c->out, info ? info->addr : 0);
    write_stream(&c->out, 0);
    json_write_uint64(&c->out, info ? info->size : 0);
    write_stream(&c->out, 0);

    if (info == NULL || info->fp == NULL) write_string(&c->out, "null");
    else write_commands(&c->out, ctx, info->fp->cmds, info->fp->cmds_cnt);
    write_stream(&c->out, 0);

    if (info != NULL && info->regs != NULL) {
        int i;
        write_stream(&c->out, '{');
        for (i = 0; i < info->reg_cnt; i++) {
            if (i > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, register2id(ctx, STACK_NO_FRAME, info->regs[i]->reg));
            write_stream(&c->out, ':');
            if (info->regs[i] == NULL) write_string(&c->out, "null");
            else write_commands(&c->out, ctx, info->regs[i]->cmds, info->regs[i]->cmds_cnt);
        }
        write_stream(&c->out, '}');
    }
    else {
        write_string(&c->out, "null");
    }
    write_stream(&c->out, 0);

    write_stream(&c->out, MARKER_EOM);
}

static void command_find_frame_info(char * token, Channel * c) {
    CommandFindFrameInfo args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args.addr = (ContextAddress)json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_find_frame_info_cache_client, c, &args, sizeof(args));
}

typedef struct CommandSymFileInfo {
    char token[256];
    char id[256];
    ContextAddress addr;
} CommandSymFileInfo;

static void command_get_sym_file_info_cache_client(void * x) {
    int err = 0;
    MemoryMap * client_map = NULL;
    MemoryMap * target_map = NULL;
    MemoryRegion * region = NULL;
    Channel * c = cache_channel();
    CommandSymFileInfo * args = (CommandSymFileInfo *)x;
    const char * sym_file = NULL;
    Context * ctx = NULL;
    int sym_error = 0;

    ctx = id2ctx(args->id);
    if (ctx == NULL) err = ERR_INV_CONTEXT;
    if (!err && memory_map_get(ctx, &client_map, &target_map) < 0) err = errno;

    if (!err) {
        unsigned i;
        for (i = 0; i < client_map->region_cnt; i++) {
            MemoryRegion * r = client_map->regions + i;
            if (r->addr <= args->addr && r->addr + r->size > args->addr) region = r;
        }
        if (region == NULL) {
            for (i = 0; i < target_map->region_cnt; i++) {
                MemoryRegion * r = target_map->regions + i;
                if (r->addr <= args->addr && r->addr + r->size > args->addr) region = r;
            }
        }

        sym_file = get_symbol_file_name(region);
        sym_error = errno;
    }

    cache_exit();

    write_stringz(&c->out, "R");
    write_stringz(&c->out, args->token);
    write_errno(&c->out, err);
    if (region != NULL) {
        write_stream(&c->out, '{');
        json_write_string(&c->out, "Addr");
        write_stream(&c->out, ':');
        json_write_uint64(&c->out, region->addr);
        write_stream(&c->out, ',');
        json_write_string(&c->out, "Size");
        write_stream(&c->out, ':');
        json_write_uint64(&c->out, region->size);
        if (sym_file != NULL) {
            write_stream(&c->out, ',');
            json_write_string(&c->out, "FileName");
            write_stream(&c->out, ':');
            json_write_string(&c->out, sym_file);
        }
        if (sym_error != 0) {
            write_stream(&c->out, ',');
            json_write_string(&c->out, "FileError");
            write_stream(&c->out, ':');
            write_error_object(&c->out, sym_error);
        }
        write_stream(&c->out, '}');
        write_stream(&c->out, 0);
    }
    else {
        write_stringz(&c->out, "null");
    }
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_sym_file_info(char * token, Channel * c) {
    CommandSymFileInfo args;

    json_read_string(&c->inp, args.id, sizeof(args.id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args.addr = (ContextAddress)json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    strlcpy(args.token, token, sizeof(args.token));
    cache_enter(command_get_sym_file_info_cache_client, c, &args, sizeof(args));
}

void ini_symbols_service(Protocol * proto) {
    static int ini_done = 0;
    if (!ini_done) {
        ini_symbols_lib();
        ini_done = 1;
    }
    add_command_handler(proto, SYMBOLS, "getContext", command_get_context);
    add_command_handler(proto, SYMBOLS, "getChildren", command_get_children);
    add_command_handler(proto, SYMBOLS, "find", command_find_first);
    add_command_handler(proto, SYMBOLS, "findByName", command_find_by_name);
    add_command_handler(proto, SYMBOLS, "findByAddr", command_find_by_addr);
    add_command_handler(proto, SYMBOLS, "findInScope", command_find_in_scope);
    add_command_handler(proto, SYMBOLS, "list", command_list);
    add_command_handler(proto, SYMBOLS, "getArrayType", command_get_array_type);
    add_command_handler(proto, SYMBOLS, "getLocationInfo", command_get_location_info);
    add_command_handler(proto, SYMBOLS, "findFrameInfo", command_find_frame_info);
    add_command_handler(proto, SYMBOLS, "getSymFileInfo", command_get_sym_file_info);
}

#endif /* SERVICE_Symbols */
