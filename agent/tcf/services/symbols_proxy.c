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
 * Symbols service - proxy implementation, gets symbols information from host.
 */

/* TODO: need to cleanup symbols cache from data that not used for long time */

#include <tcf/config.h>

#if ENABLE_SymbolsProxy

#include <assert.h>
#include <stdio.h>
#include <tcf/framework/context.h>
#include <tcf/framework/cache.h>
#include <tcf/framework/json.h>
#include <tcf/framework/events.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/symbols.h>
#include <tcf/services/vm.h>
#if ENABLE_RCBP_TEST
#  include <tcf/main/test.h>
#endif

#define HASH_SIZE (4 * MEM_USAGE_FACTOR - 1)

#define ACC_SIZE    1
#define ACC_LENGTH  2
#define ACC_OTHER   3

/* Symbols cahce, one per channel */
typedef struct SymbolsCache {
    Channel * channel;
    LINK link_root;
    LINK link_sym[HASH_SIZE];
    LINK link_find_by_name[HASH_SIZE];
    LINK link_find_by_addr[HASH_SIZE];
    LINK link_find_in_scope[HASH_SIZE];
    LINK link_list[HASH_SIZE];
    LINK link_frame[HASH_SIZE];
    LINK link_location[HASH_SIZE];
    int service_available;
} SymbolsCache;

/* Symbol properties cache */
typedef struct SymInfoCache {
    unsigned magic;
    LINK link_syms;
    AbstractCache cache;
    char * id;
    char * type_id;
    char * base_type_id;
    char * index_type_id;
    char * container_id;
    char * name;
    Context * update_owner;
    int update_policy;
    int degraded;
    int sym_class;
    int type_class;
    int has_size;
    int has_length;
    int has_lower_bound;
    int frame;
    SYM_FLAGS flags;
    ContextAddress size;
    ContextAddress length;
    int64_t lower_bound;
    char ** children_ids;
    int children_count;
    ReplyHandlerInfo * pending_get_context;
    ReplyHandlerInfo * pending_get_children;
    ErrorReport * error_get_context;
    ErrorReport * error_get_children;
    int done_context;
    int done_children;
    LINK array_syms;
    int disposed;
} SymInfoCache;

/* Cached result of get_array_symbol() */
typedef struct ArraySymCache {
    LINK link_sym;
    AbstractCache cache;
    ContextAddress length;
    ReplyHandlerInfo * pending;
    ErrorReport * error;
    char * id;
    int disposed;
} ArraySymCache;

/* Cached result of find_symbol_by_name(), find_symbol_in_scope(), find_symbol_by_addr(), enumerate_symbols() */
typedef struct FindSymCache {
    LINK link_syms;
    AbstractCache cache;
    ReplyHandlerInfo * pending;
    ErrorReport * error;
    int update_policy;
    Context * ctx;
    int frame;
    uint64_t ip;
    uint64_t addr;
    char * scope;
    char * name;
    char ** id_buf;
    int id_cnt;
    int disposed;
} FindSymCache;

typedef struct StackFrameCache {
    LINK link_syms;
    AbstractCache cache;
    ReplyHandlerInfo * pending;
    ErrorReport * error;
    Context * ctx;
    uint64_t ip;
    uint64_t address;
    uint64_t size;

    StackFrameRegisterLocation * fp;
    StackFrameRegisterLocation ** regs;
    int regs_cnt;

    int disposed;
} StackFrameCache;

typedef struct LocationInfoCache {
    LINK link_syms;
    AbstractCache cache;
    ReplyHandlerInfo * pending;
    ErrorReport * error;
    char * sym_id;
    Context * ctx;
    uint64_t ip;

    LocationInfo info;

    int disposed;
} LocationInfoCache;

#define SYM_CACHE_MAGIC 0x38254865

#define root2syms(A) ((SymbolsCache *)((char *)(A) - offsetof(SymbolsCache, link_root)))
#define syms2sym(A)  ((SymInfoCache *)((char *)(A) - offsetof(SymInfoCache, link_syms)))
#define syms2find(A) ((FindSymCache *)((char *)(A) - offsetof(FindSymCache, link_syms)))
#define sym2arr(A)   ((ArraySymCache *)((char *)(A) - offsetof(ArraySymCache, link_sym)))
#define syms2frame(A)((StackFrameCache *)((char *)(A) - offsetof(StackFrameCache, link_syms)))
#define syms2location(A)((LocationInfoCache *)((char *)(A) - offsetof(LocationInfoCache, link_syms)))

struct Symbol {
    unsigned magic;
    SymInfoCache * cache;
};

static LINK root = TCF_LIST_INIT(root);

static char ** find_next_buf = NULL;
static int find_next_pos = 0;
static int find_next_cnt = 0;

static const char * SYMBOLS = "Symbols";

#define SYMBOL_MAGIC 0x34875234

static Symbol * alloc_symbol(void) {
    Symbol * s = (Symbol *)tmp_alloc_zero(sizeof(Symbol));
    s->magic = SYMBOL_MAGIC;
    return s;
}

static unsigned hash_sym_id(const char * id) {
    int i;
    unsigned h = 0;
    for (i = 0; id[i]; i++) h += id[i];
    return h % HASH_SIZE;
}

static unsigned hash_find(Context * ctx, const char * name, uint64_t ip) {
    int i;
    unsigned h = 0;
    if (name != NULL) for (i = 0; name[i]; i++) h += name[i];
    return (h + ((uintptr_t)ctx >> 4) + (unsigned)ip) % HASH_SIZE;
}

static unsigned hash_list(Context * ctx, uint64_t ip) {
    return (((uintptr_t)ctx >> 4) + (unsigned)ip) % HASH_SIZE;
}

static unsigned hash_frame(Context * ctx) {
    return ((uintptr_t)ctx >> 4) % HASH_SIZE;
}

static SymbolsCache * get_symbols_cache(void) {
    LINK * l = NULL;
    SymbolsCache * syms = NULL;
    Channel * c = cache_channel();
    if (c == NULL) str_exception(ERR_OTHER, "get_symbols_cache(): illegal cache access");
    for (l = root.next; l != &root; l = l->next) {
        SymbolsCache * x = root2syms(l);
        if (x->channel == c) {
            syms = x;
            break;
        }
    }
    if (syms == NULL) {
        int i = 0;
        syms = (SymbolsCache *)loc_alloc_zero(sizeof(SymbolsCache));
        syms->channel = c;
        list_add_first(&syms->link_root, &root);
        for (i = 0; i < HASH_SIZE; i++) {
            list_init(syms->link_sym + i);
            list_init(syms->link_find_by_name + i);
            list_init(syms->link_find_by_addr + i);
            list_init(syms->link_find_in_scope + i);
            list_init(syms->link_list + i);
            list_init(syms->link_frame + i);
            list_init(syms->link_location + i);
        }
        channel_lock(c);
        for (i = 0; i < c->peer_service_cnt; i++) {
            if (strcmp(c->peer_service_list[i], SYMBOLS) == 0) syms->service_available = 1;
        }
    }
    return syms;
}

static void free_arr_sym_cache(ArraySymCache * a) {
    list_remove(&a->link_sym);
    a->disposed = 1;
    if (a->pending == NULL) {
        cache_dispose(&a->cache);
        release_error_report(a->error);
        loc_free(a->id);
        loc_free(a);
    }
}

static void free_sym_info_cache(SymInfoCache * c) {
    assert(c->magic == SYM_CACHE_MAGIC);
    list_remove(&c->link_syms);
    c->disposed = 1;
    if (c->pending_get_context == NULL && c->pending_get_children == NULL) {
        c->magic = 0;
        cache_dispose(&c->cache);
        loc_free(c->id);
        loc_free(c->type_id);
        loc_free(c->base_type_id);
        loc_free(c->index_type_id);
        loc_free(c->container_id);
        loc_free(c->name);
        loc_free(c->children_ids);
        if (c->update_owner != NULL) context_unlock(c->update_owner);
        release_error_report(c->error_get_context);
        release_error_report(c->error_get_children);
        while (!list_is_empty(&c->array_syms)) {
            free_arr_sym_cache(sym2arr(c->array_syms.next));
        }
        loc_free(c);
    }
}

static void free_find_sym_cache(FindSymCache * c) {
    list_remove(&c->link_syms);
    c->disposed = 1;
    if (c->pending == NULL) {
        if (find_next_buf == c->id_buf) {
            find_next_buf = NULL;
            find_next_pos = 0;
            find_next_cnt = 0;
        }
        cache_dispose(&c->cache);
        release_error_report(c->error);
        context_unlock(c->ctx);
        loc_free(c->scope);
        loc_free(c->name);
        loc_free(c->id_buf);
        loc_free(c);
    }
}

static void free_sft_sequence(StackFrameRegisterLocation * seq) {
    if (seq != NULL) {
        unsigned i = 0;
        while (i < seq->cmds_cnt) {
            LocationExpressionCommand * cmd = seq->cmds + i++;
            if (cmd->cmd == SFT_CMD_LOCATION) loc_free(cmd->args.loc.code_addr);
        }
        loc_free(seq);
    }
}

static void free_stack_frame_cache(StackFrameCache * c) {
    list_remove(&c->link_syms);
    c->disposed = 1;
    if (c->pending == NULL) {
        int i;
        cache_dispose(&c->cache);
        release_error_report(c->error);
        context_unlock(c->ctx);
        for (i = 0; i < c->regs_cnt; i++) free_sft_sequence(c->regs[i]);
        free_sft_sequence(c->fp);
        loc_free(c->regs);
        loc_free(c);
    }
}

static void free_location_commands(LocationCommands * cmds) {
    unsigned i = 0;
    while (i < cmds->cnt) {
        LocationExpressionCommand * cmd = cmds->cmds + i++;
        if (cmd->cmd == SFT_CMD_LOCATION) loc_free(cmd->args.loc.code_addr);
    }
    loc_free(cmds->cmds);
}

static void free_location_info_cache(LocationInfoCache * c) {
    list_remove(&c->link_syms);
    c->disposed = 1;
    if (c->pending == NULL) {
        cache_dispose(&c->cache);
        release_error_report(c->error);
        context_unlock(c->ctx);
        loc_free(c->sym_id);
        free_location_commands(&c->info.value_cmds);
        loc_free(c);
    }
}

static void free_symbols_cache(SymbolsCache * syms) {
    int i;
    for (i = 0; i < HASH_SIZE; i++) {
        while (!list_is_empty(syms->link_sym + i)) {
            free_sym_info_cache(syms2sym(syms->link_sym[i].next));
        }
        while (!list_is_empty(syms->link_find_by_name + i)) {
            free_find_sym_cache(syms2find(syms->link_find_by_name[i].next));
        }
        while (!list_is_empty(syms->link_find_by_addr + i)) {
            free_find_sym_cache(syms2find(syms->link_find_by_addr[i].next));
        }
        while (!list_is_empty(syms->link_find_in_scope + i)) {
            free_find_sym_cache(syms2find(syms->link_find_in_scope[i].next));
        }
        while (!list_is_empty(syms->link_list + i)) {
            free_find_sym_cache(syms2find(syms->link_list[i].next));
        }
        while (!list_is_empty(syms->link_frame + i)) {
            free_stack_frame_cache(syms2frame(syms->link_frame[i].next));
        }
    }
    channel_unlock(syms->channel);
    list_remove(&syms->link_root);
    loc_free(syms);
}

static Channel * get_channel(SymbolsCache * syms) {
    if (is_channel_closed(syms->channel)) exception(ERR_CHANNEL_CLOSED);
    if (!syms->service_available) str_exception(ERR_SYM_NOT_FOUND, "Symbols service not available");
    return syms->channel;
}

static void read_context_data(InputStream * inp, const char * name, void * args) {
    char id[256];
    SymInfoCache * s = (SymInfoCache *)args;
    if (strcmp(name, "ID") == 0) { json_read_string(inp, id, sizeof(id)); assert(strcmp(id, s->id) == 0); }
    else if (strcmp(name, "OwnerID") == 0) { json_read_string(inp, id, sizeof(id)); s->update_owner = id2ctx(id); }
    else if (strcmp(name, "Name") == 0) s->name = json_read_alloc_string(inp);
    else if (strcmp(name, "UpdatePolicy") == 0) s->update_policy = json_read_long(inp);
    else if (strcmp(name, "Class") == 0) s->sym_class = json_read_long(inp);
    else if (strcmp(name, "TypeClass") == 0) s->type_class = json_read_long(inp);
    else if (strcmp(name, "TypeID") == 0) s->type_id = json_read_alloc_string(inp);
    else if (strcmp(name, "BaseTypeID") == 0) s->base_type_id = json_read_alloc_string(inp);
    else if (strcmp(name, "IndexTypeID") == 0) s->index_type_id = json_read_alloc_string(inp);
    else if (strcmp(name, "ContainerID") == 0) s->container_id = json_read_alloc_string(inp);
    else if (strcmp(name, "Size") == 0) { s->size = json_read_long(inp); s->has_size = 1; }
    else if (strcmp(name, "Length") == 0) { s->length = json_read_long(inp); s->has_length = 1; }
    else if (strcmp(name, "LowerBound") == 0) { s->lower_bound = json_read_int64(inp); s->has_lower_bound = 1; }
    else if (strcmp(name, "Flags") == 0) s->flags = json_read_ulong(inp);
    else if (strcmp(name, "Frame") == 0) s->frame = (int)json_read_long(inp);
    else json_skip_object(inp);
}

static void validate_context(Channel * c, void * args, int error) {
    Trap trap;
    SymInfoCache * s = (SymInfoCache *)args;
    assert(s->pending_get_context != NULL);
    assert(s->error_get_context == NULL);
    assert(s->update_owner == NULL);
    assert(!s->done_context);
    assert(!s->degraded);
    if (set_trap(&trap)) {
        s->pending_get_context = NULL;
        s->done_context = 1;
        if (!error) {
            error = read_errno(&c->inp);
            json_read_struct(&c->inp, read_context_data, s);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
            if (!error && s->update_owner == NULL) error = ERR_INV_CONTEXT;
            if (!error && s->update_owner->exited) error = ERR_ALREADY_EXITED;
        }
        clear_trap(&trap);
        if (s->update_owner != NULL) context_lock(s->update_owner);
    }
    else {
        error = trap.error;
        s->update_owner = NULL;
    }
    s->error_get_context = get_error_report(error);
    cache_notify(&s->cache);
    if (s->disposed) free_sym_info_cache(s);
}

static SymInfoCache * get_sym_info_cache(const Symbol * sym, int acc_mode) {
    Trap trap;
    SymInfoCache * s = sym->cache;
    assert(sym->magic == SYMBOL_MAGIC);
    assert(s->magic == SYM_CACHE_MAGIC);
    assert(s->id != NULL);
    if (!set_trap(&trap)) return NULL;
    if (s->pending_get_context != NULL) {
        cache_wait(&s->cache);
    }
    if (s->error_get_context != NULL) {
        exception(set_error_report_errno(s->error_get_context));
    }
    if (s->done_context && s->degraded) {
        /* Symbol info is partially outdated */
        int update = 0;
        assert(s->update_owner != NULL);
        assert(context_has_state(s->update_owner));
        switch (acc_mode) {
        case ACC_SIZE:
        case ACC_LENGTH:
            if (s->type_class != TYPE_CLASS_ARRAY) break;
            update = 1;
            break;
        }
        if (update) {
            if (!s->update_owner->stopped) exception(ERR_IS_RUNNING);
            s->degraded = 0;
            s->done_context = 0;
            s->has_size = 0;
            s->has_length = 0;
            s->has_lower_bound = 0;
            context_unlock(s->update_owner);
            loc_free(s->type_id);
            loc_free(s->base_type_id);
            loc_free(s->index_type_id);
            loc_free(s->container_id);
            loc_free(s->name);
            s->update_owner = NULL;
            s->type_id = NULL;
            s->base_type_id = NULL;
            s->index_type_id = NULL;
            s->container_id = NULL;
            s->name = NULL;
        }
    }
    if (!s->done_context) {
        Channel * c = cache_channel();
        if (c == NULL || is_channel_closed(c)) exception(ERR_SYM_NOT_FOUND);
        s->pending_get_context = protocol_send_command(c, SYMBOLS, "getContext", validate_context, s);
        json_write_string(&c->out, s->id);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&s->cache);
    }
    clear_trap(&trap);
    return s;
}

static char ** string_to_symbol_list(char * id, int * cnt) {
    if (id[0]) {
        char ** buf = (char **)loc_alloc_zero(sizeof(char *) * 2 + strlen(id) + 1);
        buf[0] = (char *)(buf + 2);
        strcpy(buf[0], id);
        *cnt = 1;
        return buf;
    }
    *cnt = 0;
    return NULL;
}

static char ** read_symbol_list(InputStream * inp, int * id_cnt) {
    char id[256];
    if (peek_stream(inp) == '[') return json_read_alloc_string_array(inp, id_cnt);
    json_read_string(inp, id, sizeof(id));
    return string_to_symbol_list(id, id_cnt);
}

static void validate_find(Channel * c, void * args, int error) {
    Trap trap;
    FindSymCache * f = (FindSymCache *)args;
    assert(f->pending != NULL);
    assert(f->error == NULL);
    if (set_trap(&trap)) {
        f->pending = NULL;
        if (!error) {
            error = read_errno(&c->inp);
            f->id_buf = read_symbol_list(&c->inp, &f->id_cnt);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
        }
        clear_trap(&trap);
    }
    else {
        error = trap.error;
    }
    f->error = get_error_report(error);
    cache_notify(&f->cache);
    if (f->disposed) free_find_sym_cache(f);
}

int find_symbol_by_name(Context * ctx, int frame, ContextAddress addr, const char * name, Symbol ** sym) {
    uint64_t ip = 0;
    LINK * l = NULL;
    SymbolsCache * syms = NULL;
    FindSymCache * f = NULL;
    unsigned h;
    Trap trap;

    if (!set_trap(&trap)) return -1;

    if (frame == STACK_NO_FRAME) {
        ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
        ip = addr;
    }
    else {
        StackFrame * info = NULL;
        if (frame == STACK_TOP_FRAME && (frame = get_top_frame(ctx)) < 0) exception(errno);;
        if (get_frame_info(ctx, frame, &info) < 0) exception(errno);
        if (read_reg_value(info, get_PC_definition(ctx), &ip) < 0) exception(errno);
    }

    h = hash_find(ctx, name, ip);
    syms = get_symbols_cache();
    for (l = syms->link_find_by_name[h].next; l != syms->link_find_by_name + h; l = l->next) {
        FindSymCache * c = syms2find(l);
        if (c->ctx == ctx && c->frame == frame && c->ip == ip && strcmp(c->name, name) == 0) {
            f = c;
            break;
        }
    }

#if ENABLE_RCBP_TEST
    if (f == NULL && !syms->service_available) {
        void * address = NULL;
        int sym_class = 0;
        if (find_test_symbol(ctx, name, &address, &sym_class) >= 0) {
            char bf[256];
            if (f == NULL) {
                f = (FindSymCache *)loc_alloc_zero(sizeof(FindSymCache));
                list_add_first(&f->link_syms, syms->link_find_by_name + h);
                context_lock(f->ctx = ctx);
                f->name = loc_strdup(name);
                f->ip = ip;
            }
            else {
                release_error_report(f->error);
                f->error = NULL;
                loc_free(f->id_buf);
                f->id_cnt = 0;
            }
            f->update_policy = UPDATE_ON_MEMORY_MAP_CHANGES;
            snprintf(bf, sizeof(bf), "@T.%X.%"PRIX64".%s", sym_class,
                    (uint64_t)(uintptr_t)address, context_get_group(ctx, CONTEXT_GROUP_SYMBOLS)->id);
            f->id_buf = string_to_symbol_list(bf, &f->id_cnt);
        }
    }
#endif

    if (f == NULL) {
        Channel * c = get_channel(syms);
        f = (FindSymCache *)loc_alloc_zero(sizeof(FindSymCache));
        list_add_first(&f->link_syms, syms->link_find_by_name + h);
        context_lock(f->ctx = ctx);
        f->frame = frame;
        f->ip = ip;
        f->name = loc_strdup(name);
        f->update_policy = UPDATE_ON_MEMORY_MAP_CHANGES;
        f->pending = protocol_send_command(c, SYMBOLS, "findByName", validate_find, f);
        if (frame != STACK_NO_FRAME) {
            json_write_string(&c->out, frame2id(ctx, frame));
        }
        else {
            json_write_string(&c->out, ctx->id);
        }
        write_stream(&c->out, 0);
        json_write_uint64(&c->out, ip);
        write_stream(&c->out, 0);
        json_write_string(&c->out, name);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&f->cache);
    }
    else if (f->pending != NULL) {
        cache_wait(&f->cache);
    }
    else if (f->error != NULL) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Symbol '%s' not found", name);
        exception(set_errno(set_error_report_errno(f->error), msg));
    }
    else if (id2symbol(f->id_buf[0], sym) < 0) {
        exception(errno);
    }
    else {
        find_next_buf = f->id_buf;
        find_next_cnt = f->id_cnt;
        find_next_pos = 1;
    }
    clear_trap(&trap);
    return 0;
}

int find_symbol_by_addr(Context * ctx, int frame, ContextAddress addr, Symbol ** sym) {
    uint64_t ip = 0;
    LINK * l = NULL;
    SymbolsCache * syms = NULL;
    FindSymCache * f = NULL;
    unsigned h;
    Trap trap;

    if (!set_trap(&trap)) return -1;

    if (frame == STACK_NO_FRAME) {
        ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
        ip = addr;
    }
    else {
        StackFrame * info = NULL;
        if (frame == STACK_TOP_FRAME && (frame = get_top_frame(ctx)) < 0) exception(errno);;
        if (get_frame_info(ctx, frame, &info) < 0) exception(errno);
        if (read_reg_value(info, get_PC_definition(ctx), &ip) < 0) exception(errno);
    }

    h = hash_find(ctx, NULL, ip);
    syms = get_symbols_cache();
    for (l = syms->link_find_by_addr[h].next; l != syms->link_find_by_addr + h; l = l->next) {
        FindSymCache * c = syms2find(l);
        if (c->ctx == ctx && c->frame == frame && c->ip == ip && c->addr == addr) {
            f = c;
            break;
        }
    }

    if (f == NULL) {
        Channel * c = get_channel(syms);
        f = (FindSymCache *)loc_alloc_zero(sizeof(FindSymCache));
        list_add_first(&f->link_syms, syms->link_find_by_addr + h);
        context_lock(f->ctx = ctx);
        f->frame = frame;
        f->ip = ip;
        f->addr = addr;
        f->update_policy = ip ? UPDATE_ON_EXE_STATE_CHANGES : UPDATE_ON_MEMORY_MAP_CHANGES;
        f->pending = protocol_send_command(c, SYMBOLS, "findByAddr", validate_find, f);
        if (frame != STACK_NO_FRAME) {
            json_write_string(&c->out, frame2id(ctx, frame));
        }
        else {
            json_write_string(&c->out, ctx->id);
        }
        write_stream(&c->out, 0);
        json_write_uint64(&c->out, addr);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&f->cache);
    }
    else if (f->pending != NULL) {
        cache_wait(&f->cache);
    }
    else if (f->error != NULL) {
        exception(set_error_report_errno(f->error));
    }
    else if (id2symbol(f->id_buf[0], sym) < 0) {
        exception(errno);
    }
    else {
        find_next_buf = f->id_buf;
        find_next_cnt = f->id_cnt;
        find_next_pos = 1;
    }
    clear_trap(&trap);
    return 0;
}

int find_symbol_in_scope(Context * ctx, int frame, ContextAddress addr, Symbol * scope, const char * name, Symbol ** sym) {
    uint64_t ip = 0;
    LINK * l = NULL;
    SymbolsCache * syms = NULL;
    FindSymCache * f = NULL;
    unsigned h;
    Trap trap;

    if (!set_trap(&trap)) return -1;

    if (frame == STACK_NO_FRAME) {
        ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
        ip = addr;
    }
    else {
        StackFrame * info = NULL;
        if (frame == STACK_TOP_FRAME && (frame = get_top_frame(ctx)) < 0) exception(errno);;
        if (get_frame_info(ctx, frame, &info) < 0) exception(errno);
        if (read_reg_value(info, get_PC_definition(ctx), &ip) < 0) exception(errno);
    }

    h = hash_find(ctx, name, ip);
    syms = get_symbols_cache();
    for (l = syms->link_find_in_scope[h].next; l != syms->link_find_in_scope + h; l = l->next) {
        FindSymCache * c = syms2find(l);
        if (c->ctx == ctx && c->frame == frame && c->ip == ip && strcmp(c->name, name) == 0) {
            if (scope == NULL && c->scope == NULL) {
                f = c;
                break;
            }
            if (scope == NULL || c->scope == NULL) continue;
            if (strcmp(scope->cache->id, c->scope) == 0) {
                f = c;
                break;
            }
        }
    }

    if (f == NULL) {
        Channel * c = get_channel(syms);
        f = (FindSymCache *)loc_alloc_zero(sizeof(FindSymCache));
        list_add_first(&f->link_syms, syms->link_find_in_scope + h);
        context_lock(f->ctx = ctx);
        f->frame = frame;
        f->ip = ip;
        if (scope != NULL) f->scope = loc_strdup(scope->cache->id);
        f->name = loc_strdup(name);
        f->update_policy = UPDATE_ON_MEMORY_MAP_CHANGES;
        f->pending = protocol_send_command(c, SYMBOLS, "findInScope", validate_find, f);
        if (frame != STACK_NO_FRAME) {
            json_write_string(&c->out, frame2id(ctx, frame));
        }
        else {
            json_write_string(&c->out, ctx->id);
        }
        write_stream(&c->out, 0);
        json_write_uint64(&c->out, ip);
        write_stream(&c->out, 0);
        json_write_string(&c->out, scope ? scope->cache->id : NULL);
        write_stream(&c->out, 0);
        json_write_string(&c->out, name);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&f->cache);
    }
    else if (f->pending != NULL) {
        cache_wait(&f->cache);
    }
    else if (f->error != NULL) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Symbol '%s' not found", name);
        exception(set_errno(set_error_report_errno(f->error), msg));
    }
    else if (id2symbol(f->id_buf[0], sym) < 0) {
        exception(errno);
    }
    else {
        find_next_buf = f->id_buf;
        find_next_cnt = f->id_cnt;
        find_next_pos = 1;
    }
    clear_trap(&trap);
    return 0;
}

int find_next_symbol(Symbol ** sym) {
    if (find_next_buf != NULL && find_next_pos < find_next_cnt) {
        if (id2symbol(find_next_buf[find_next_pos], sym) < 0) return -1;
        find_next_pos++;
        return 0;
    }
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

int enumerate_symbols(Context * ctx, int frame, EnumerateSymbolsCallBack * func, void * args) {
    uint64_t ip = 0;
    unsigned h;
    LINK * l;
    Trap trap;
    SymbolsCache * syms = NULL;
    FindSymCache * f = NULL;

    if (!set_trap(&trap)) return -1;

    if (frame == STACK_NO_FRAME) {
        ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
    }
    else {
        StackFrame * info = NULL;
        if (frame == STACK_TOP_FRAME && (frame = get_top_frame(ctx)) < 0) exception(errno);;
        if (get_frame_info(ctx, frame, &info) < 0) exception(errno);
        if (read_reg_value(info, get_PC_definition(ctx), &ip) < 0) exception(errno);
    }

    h = hash_list(ctx, ip);
    syms = get_symbols_cache();
    for (l = syms->link_list[h].next; l != syms->link_list + h; l = l->next) {
        FindSymCache * c = syms2find(l);
        if (c->ctx == ctx && c->frame == frame && c->ip == ip) {
            f = c;
            break;
        }
    }

    if (f == NULL) {
        Channel * c = get_channel(syms);
        f = (FindSymCache *)loc_alloc_zero(sizeof(FindSymCache));
        list_add_first(&f->link_syms, syms->link_list + h);
        context_lock(f->ctx = ctx);
        f->frame = frame;
        f->ip = ip;
        f->update_policy = UPDATE_ON_MEMORY_MAP_CHANGES;
        f->pending = protocol_send_command(c, SYMBOLS, "list", validate_find, f);
        if (frame != STACK_NO_FRAME) {
            json_write_string(&c->out, frame2id(ctx, frame));
        }
        else {
            json_write_string(&c->out, ctx->id);
        }
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&f->cache);
    }
    else if (f->pending != NULL) {
        cache_wait(&f->cache);
    }
    else if (f->error != NULL) {
        exception(set_error_report_errno(f->error));
    }
    else {
        int i;
        for (i = 0; i < f->id_cnt; i++) {
            Symbol * sym = NULL;
            if (id2symbol(f->id_buf[i], &sym) < 0) exception(errno);
            func(args, sym);
        }
    }
    clear_trap(&trap);
    return 0;
}

const char * symbol2id(const Symbol * sym) {
    SymInfoCache * s = sym->cache;
    assert(s->magic == SYM_CACHE_MAGIC);
    assert(s->id != NULL);
    return s->id;
}

int id2symbol(const char * id, Symbol ** sym) {
    LINK * l;
    SymInfoCache * s = NULL;
    unsigned h = hash_sym_id(id);
    SymbolsCache * syms = get_symbols_cache();

    for (l = syms->link_sym[h].next; l != syms->link_sym + h; l = l->next) {
        SymInfoCache * x = syms2sym(l);
        if (strcmp(x->id, id) == 0) {
            s = x;
            break;
        }
    }
    if (s == NULL) {
        s = (SymInfoCache *)loc_alloc_zero(sizeof(SymInfoCache));
        s->magic = SYM_CACHE_MAGIC;
        s->id = loc_strdup(id);
        s->frame = STACK_NO_FRAME;
        list_add_first(&s->link_syms, syms->link_sym + h);
        list_init(&s->array_syms);
#if ENABLE_RCBP_TEST
        if (strncmp(id, "@T.", 3) == 0) {
            int sym_class = 0;
            uint64_t address = 0;
            char ctx_id[256];
            if (sscanf(id, "@T.%X.%"SCNx64".%255s", &sym_class, &address, ctx_id) == 3) {
                s->done_context = 1;
                s->sym_class = sym_class;
                s->update_policy = UPDATE_ON_MEMORY_MAP_CHANGES;
                s->update_owner = id2ctx(ctx_id);
                if (s->update_owner != NULL) context_lock(s->update_owner);
            }
        }
#endif
    }
    *sym = alloc_symbol();
    (*sym)->cache = s;
    return 0;
}

/*************** Functions for retrieving symbol properties ***************************************/

int get_symbol_class(const Symbol * sym, int * symbol_class) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    *symbol_class = c->sym_class;
    return 0;
}

int get_symbol_type(const Symbol * sym, Symbol ** type) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    if (c->type_id && strcmp(c->type_id, c->id)) return id2symbol(c->type_id, type);
    *type = (Symbol *)sym;
    return 0;
}

int get_symbol_type_class(const Symbol * sym, int * type_class) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    *type_class = c->type_class;
    return 0;
}

int get_symbol_update_policy(const Symbol * sym, char ** id, int * policy) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    if (c->update_owner == NULL) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    *id = c->update_owner->id;
    *policy = c->update_policy;
    return 0;
}

int get_symbol_name(const Symbol * sym, char ** name) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    *name = c->name;
    return 0;
}

int get_symbol_base_type(const Symbol * sym, Symbol ** type) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    if (c->base_type_id) return id2symbol(c->base_type_id, type);
    return 0;
}

int get_symbol_index_type(const Symbol * sym, Symbol ** type) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    if (c->index_type_id) return id2symbol(c->index_type_id, type);
    return 0;
}

int get_symbol_container(const Symbol * sym, Symbol ** container) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    if (c->container_id) return id2symbol(c->container_id, container);
    return 0;
}

int get_symbol_size(const Symbol * sym, ContextAddress * size) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_SIZE);
    if (c == NULL) return -1;
    if (!c->has_size) {
        set_errno(ERR_OTHER, "Debug info not available");
        return -1;
    }
    *size = c->size;
    return 0;
}

int get_symbol_length(const Symbol * sym, ContextAddress * length) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_LENGTH);
    if (c == NULL) return -1;
    if (c->has_length) {
        *length = c->length;
        return 0;
    }
    errno = ERR_INV_CONTEXT;
    return -1;
}

int get_symbol_lower_bound(const Symbol * sym, int64_t * lower_bound) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    if (!c->has_lower_bound) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    *lower_bound = c->lower_bound;
    return 0;
}

int get_symbol_flags(const Symbol * sym, SYM_FLAGS * flags) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    *flags = c->flags;
    return 0;
}

int get_symbol_frame(const Symbol * sym, Context ** ctx, int * frame) {
    SymInfoCache * c = get_sym_info_cache(sym, ACC_OTHER);
    if (c == NULL) return -1;
    *ctx = c->update_owner;
    *frame = c->frame;
    return 0;
}

static void validate_children(Channel * c, void * args, int error) {
    Trap trap;
    SymInfoCache * s = (SymInfoCache *)args;
    assert(s->pending_get_children != NULL);
    assert(s->error_get_children == NULL);
    assert(!s->done_children);
    if (set_trap(&trap)) {
        s->pending_get_children = NULL;
        s->done_children = 1;
        if (!error) {
            error = read_errno(&c->inp);
            s->children_ids = read_symbol_list(&c->inp, &s->children_count);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
        }
        clear_trap(&trap);
    }
    else {
        error = trap.error;
    }
    s->error_get_children = get_error_report(error);
    cache_notify(&s->cache);
    if (s->disposed) free_sym_info_cache(s);
}

int get_symbol_children(const Symbol * sym, Symbol *** children, int * count) {
    Trap trap;
    SymInfoCache * s = get_sym_info_cache(sym, ACC_OTHER);
    *children = NULL;
    *count = 0;
    if (s == NULL) return -1;
    if (!set_trap(&trap)) return -1;
    if (s->pending_get_children) {
        cache_wait(&s->cache);
    }
    else if (s->error_get_children) {
        exception(set_error_report_errno(s->error_get_children));
    }
    else if (!s->done_children) {
        Channel * c = cache_channel();
        if (c == NULL || is_channel_closed(c)) exception(ERR_SYM_NOT_FOUND);
        s->pending_get_children = protocol_send_command(c, SYMBOLS, "getChildren", validate_children, s);
        json_write_string(&c->out, s->id);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&s->cache);
    }
    else if (s->children_count > 0) {
        int i, cnt = s->children_count;
        Symbol ** buf = (Symbol **)tmp_alloc(cnt * sizeof(Symbol *));
        for (i = 0; i < cnt; i++) {
            if (id2symbol(s->children_ids[i], buf + i) < 0) exception(errno);
        }
        *children = buf;
        *count = cnt;
    }
    clear_trap(&trap);
    return 0;
}

static void validate_type_id(Channel * c, void * args, int error) {
    Trap trap;
    ArraySymCache * s = (ArraySymCache *)args;
    assert(s->pending != NULL);
    assert(s->error == NULL);
    assert(s->id == NULL);
    if (set_trap(&trap)) {
        s->pending = NULL;
        if (!error) {
            error = read_errno(&c->inp);
            s->id = json_read_alloc_string(&c->inp);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
        }
        clear_trap(&trap);
    }
    else {
        error = trap.error;
    }
    s->error = get_error_report(error);
    cache_notify(&s->cache);
    if (s->disposed) free_arr_sym_cache(s);
}

int get_array_symbol(const Symbol * sym, ContextAddress length, Symbol ** ptr) {
    LINK * l;
    Trap trap;
    ArraySymCache * a = NULL;
    SymInfoCache * s = get_sym_info_cache(sym, ACC_OTHER);
    if (s == NULL) return -1;
    if (!set_trap(&trap)) return -1;
    for (l = s->array_syms.next; l != &s->array_syms; l = l->next) {
        ArraySymCache * x = sym2arr(l);
        if (x->length == length) {
            a = x;
            break;
        }
    }
    if (a == NULL) {
        Channel * c = cache_channel();
        if (c == NULL || is_channel_closed(c)) exception(ERR_SYM_NOT_FOUND);
        a = (ArraySymCache *)loc_alloc_zero(sizeof(*a));
        list_add_first(&a->link_sym, &s->array_syms);
        a->length = length;
        a->pending = protocol_send_command(c, SYMBOLS, "getArrayType", validate_type_id, a);
        json_write_string(&c->out, s->id);
        write_stream(&c->out, 0);
        json_write_uint64(&c->out, length);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&a->cache);
    }
    else if (a->pending != NULL) {
        cache_wait(&a->cache);
    }
    else if (a->error != NULL) {
        exception(set_error_report_errno(a->error));
    }
    else if (id2symbol(a->id, ptr) < 0) {
        exception(errno);
    }
    clear_trap(&trap);
    return 0;
}

/*************************************************************************************************/

static LocationCommands location_cmds = { NULL, 0, 0};

static int trace_regs_cnt = 0;
static int trace_regs_max = 0;
static StackFrameRegisterLocation ** trace_regs = NULL;

static int id2register_error = 0;

ContextAddress is_plt_section(Context * ctx, ContextAddress addr) {
    /* TODO: is_plt_section() in symbols proxy */
    return 0;
}

static void read_dwarf_location_params(InputStream * inp, const char * nm, void * arg) {
    LocationExpressionCommand * cmd = (LocationExpressionCommand *)arg;
    if (strcmp(nm, "Machine") == 0) cmd->args.loc.reg_id_scope.machine = (uint16_t)json_read_long(inp);
    else if (strcmp(nm, "ABI") == 0) cmd->args.loc.reg_id_scope.os_abi = (uint8_t)json_read_long(inp);
    else if (strcmp(nm, "FPABI") == 0) cmd->args.loc.reg_id_scope.fp_abi = (uint8_t)json_read_long(inp);
    else if (strcmp(nm, "ELF64") == 0) cmd->args.loc.reg_id_scope.elf64 = (uint8_t)json_read_boolean(inp);
    else if (strcmp(nm, "RegIdType") == 0) cmd->args.loc.reg_id_scope.id_type = (uint8_t)json_read_long(inp);
    else if (strcmp(nm, "AddrSize") == 0) cmd->args.loc.addr_size = (size_t)json_read_long(inp);
    else if (strcmp(nm, "BigEndian") == 0) cmd->args.loc.reg_id_scope.big_endian = (uint8_t)json_read_boolean(inp);
}

static void read_location_command(InputStream * inp, void * args) {
    char id[256];
    size_t val_size = 0;
    Context * ctx = NULL;
    int frame = STACK_NO_FRAME;
    LocationExpressionCommand * cmd = NULL;
    if (location_cmds.cnt >= location_cmds.max) {
        location_cmds.max += 16;
        location_cmds.cmds = (LocationExpressionCommand *)loc_realloc(location_cmds.cmds,
            location_cmds.max * sizeof(LocationExpressionCommand));
    }
    cmd = location_cmds.cmds + location_cmds.cnt++;
    memset(cmd, 0, sizeof(*cmd));
    cmd->cmd = json_read_long(inp);
    switch (cmd->cmd) {
    case SFT_CMD_NUMBER:
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.num = json_read_int64(inp);
        break;
    case SFT_CMD_ARG:
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.num = (unsigned)json_read_ulong(inp);
        break;
    case SFT_CMD_RD_REG:
    case SFT_CMD_WR_REG:
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        json_read_string(inp, id, sizeof(id));
        if (id2register(id, &ctx, &frame, &cmd->args.reg) < 0) id2register_error = errno;
        break;
    case SFT_CMD_RD_MEM:
    case SFT_CMD_WR_MEM:
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.mem.size = json_read_ulong(inp);
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.mem.big_endian = json_read_boolean(inp);
        break;
    case SFT_CMD_LOCATION:
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.loc.code_addr = (uint8_t *)json_read_alloc_binary(inp, &cmd->args.loc.code_size);
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        json_read_struct(inp, read_dwarf_location_params, cmd);
        cmd->args.loc.func = evaluate_vm_expression;
        break;
    case SFT_CMD_PIECE:
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.piece.bit_offs = (unsigned)json_read_ulong(inp);
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.piece.bit_size = (unsigned)json_read_ulong(inp);
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        if (json_read_string(inp, id, sizeof(id))) {
            if (id2register(id, &ctx, &frame, &cmd->args.piece.reg) < 0) id2register_error = errno;
        }
        if (read_stream(inp) != ',') exception(ERR_JSON_SYNTAX);
        cmd->args.piece.value = json_read_alloc_binary(inp, &val_size);
        if (cmd->args.piece.value != NULL && val_size < (cmd->args.piece.bit_size + 7) / 8) {
            exception(ERR_JSON_SYNTAX);
        }
        break;
    }
}

static void read_location_command_array(InputStream * inp, LocationCommands * cmds) {
    location_cmds.cnt = 0;
    if (json_read_array(inp, read_location_command, NULL)) {
        cmds->cmds = (LocationExpressionCommand *)loc_alloc(location_cmds.cnt * sizeof(LocationExpressionCommand));
        memcpy(cmds->cmds, location_cmds.cmds, location_cmds.cnt * sizeof(LocationExpressionCommand));
        cmds->cnt = cmds->max = location_cmds.cnt;
    }
}

static void read_location_attrs(InputStream * inp, const char * name, void * x) {
    LocationInfoCache * f = (LocationInfoCache *)x;
    if (strcmp(name, "ArgCnt") == 0) f->info.args_cnt = (unsigned)json_read_ulong(inp);
    else if (strcmp(name, "CodeAddr") == 0) f->info.code_addr = (ContextAddress)json_read_uint64(inp);
    else if (strcmp(name, "CodeSize") == 0) f->info.code_size = (ContextAddress)json_read_uint64(inp);
    else if (strcmp(name, "BigEndian") == 0) f->info.big_endian = json_read_boolean(inp);
    else if (strcmp(name, "ValueCmds") == 0) read_location_command_array(inp, &f->info.value_cmds);
    else json_skip_object(inp);
}

static void validate_location_info(Channel * c, void * args, int error) {
    Trap trap;
    LocationInfoCache * f = (LocationInfoCache *)args;
    assert(f->pending != NULL);
    assert(f->error == NULL);
    if (set_trap(&trap)) {
        f->pending = NULL;
        if (!error) {
            id2register_error = 0;
            error = read_errno(&c->inp);
            json_read_struct(&c->inp, read_location_attrs, f);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
            if (!error && id2register_error) error = id2register_error;
        }
        clear_trap(&trap);
    }
    else {
        error = trap.error;
    }
    f->error = get_error_report(error);
    cache_notify(&f->cache);
    if (f->disposed) free_location_info_cache(f);
}

int get_location_info(const Symbol * sym, LocationInfo ** loc) {
    Trap trap;
    unsigned h;
    LINK * l;
    SymbolsCache * syms = NULL;
    LocationInfoCache * f = NULL;
    SymInfoCache * sym_cache = NULL;
    Context * ctx = NULL;
    Context * prs = NULL;
    uint64_t ip = 0;

    sym_cache = get_sym_info_cache(sym, ACC_OTHER);
    if (sym_cache == NULL) return -1;

    /* Here we assume that symbol location info is valid for all threads in same memory space */
    ctx = sym_cache->update_owner;
    prs = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);

    if (!set_trap(&trap)) return -1;

    if (sym_cache->frame != STACK_NO_FRAME) {
        StackFrame * frame = NULL;
        if (get_frame_info(ctx, sym_cache->frame, &frame) < 0) exception(errno);
        if (read_reg_value(frame, get_PC_definition(ctx), &ip) < 0) exception(errno);
    }

    h = hash_sym_id(sym_cache->id);
    syms = get_symbols_cache();
    for (l = syms->link_location[h].next; l != syms->link_location + h; l = l->next) {
        LocationInfoCache * c = syms2location(l);
        if (c->ctx == prs && strcmp(sym_cache->id, c->sym_id) == 0) {
            if (c->pending != NULL) {
                cache_wait(&c->cache);
            }
            else if (c->info.code_size == 0 ||
                    (c->info.code_addr <= ip && c->info.code_addr + c->info.code_size > ip)) {
                f = c;
                break;
            }
        }
    }

    assert(f == NULL || f->pending == NULL);

    if (f == NULL) {
        Channel * c = get_channel(syms);
        f = (LocationInfoCache *)loc_alloc_zero(sizeof(LocationInfoCache));
        list_add_first(&f->link_syms, syms->link_location + h);
        context_lock(f->ctx = prs);
        f->ip = ip;
        f->sym_id = loc_strdup(sym_cache->id);
#if ENABLE_RCBP_TEST
        if (strncmp(f->sym_id, "@T.", 3) == 0) {
            int sym_class = 0;
            uint64_t address = 0;
            char ctx_id[256];
            if (sscanf(f->sym_id, "@T.%X.%"SCNx64".%255s", &sym_class, &address, ctx_id) == 3) {
                location_cmds.cnt = 0;
                f->info.value_cmds.cmds = (LocationExpressionCommand *)loc_alloc(location_cmds.cnt * sizeof(LocationExpressionCommand));
                memcpy(f->info.value_cmds.cmds, location_cmds.cmds, location_cmds.cnt * sizeof(LocationExpressionCommand));
                f->info.value_cmds.cnt = f->info.value_cmds.max = location_cmds.cnt;
            }
        }
#endif
        f->pending = protocol_send_command(c, SYMBOLS, "getLocationInfo", validate_location_info, f);
        json_write_string(&c->out, f->sym_id);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&f->cache);
    }
    else if (f->error != NULL) {
        exception(set_error_report_errno(f->error));
    }
    else {
        *loc = &f->info;
    }

    clear_trap(&trap);
    return 0;
}

static void read_stack_trace_register(InputStream * inp, const char * id, void * args) {
    if (trace_regs_cnt >= trace_regs_max) {
        trace_regs_max += 16;
        trace_regs = (StackFrameRegisterLocation **)loc_realloc(trace_regs, trace_regs_max * sizeof(StackFrameRegisterLocation *));
    }
    location_cmds.cnt = 0;
    if (json_read_array(inp, read_location_command, NULL)) {
        Context * ctx = NULL;
        int frame = STACK_NO_FRAME;
        StackFrameRegisterLocation * reg = (StackFrameRegisterLocation *)loc_alloc(
            sizeof(StackFrameRegisterLocation) + (location_cmds.cnt - 1) * sizeof(LocationExpressionCommand));
        if (id2register(id, &ctx, &frame, &reg->reg) < 0) {
            id2register_error = errno;
            loc_free(reg);
        }
        else {
            reg->cmds_cnt = location_cmds.cnt;
            reg->cmds_max = location_cmds.cnt;
            memcpy(reg->cmds, location_cmds.cmds, location_cmds.cnt * sizeof(LocationExpressionCommand));
            trace_regs[trace_regs_cnt++] = reg;
        }
    }
}

static void validate_frame(Channel * c, void * args, int error) {
    Trap trap;
    StackFrameCache * f = (StackFrameCache *)args;
    assert(f->pending != NULL);
    assert(f->error == NULL);
    if (set_trap(&trap)) {
        f->pending = NULL;
        if (!error) {
            uint64_t addr, size;
            id2register_error = 0;
            error = read_errno(&c->inp);
            addr = json_read_uint64(&c->inp);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            size = json_read_uint64(&c->inp);
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (error || size == 0) {
                f->address = f->ip & ~(uint64_t)3;
                f->size = 4;
            }
            else {
                assert(addr <= f->ip);
                assert(addr + size > f->ip);
                f->address = addr;
                f->size = size;
            }
            location_cmds.cnt = 0;
            if (json_read_array(&c->inp, read_location_command, NULL)) {
                f->fp = (StackFrameRegisterLocation *)loc_alloc(sizeof(StackFrameRegisterLocation) +
                    (location_cmds.cnt - 1) * sizeof(LocationExpressionCommand));
                f->fp->reg = NULL;
                f->fp->cmds_cnt = location_cmds.cnt;
                f->fp->cmds_max = location_cmds.cnt;
                memcpy(f->fp->cmds, location_cmds.cmds, location_cmds.cnt * sizeof(LocationExpressionCommand));
            }
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            trace_regs_cnt = 0;
            if (json_read_struct(&c->inp, read_stack_trace_register, NULL)) {
                f->regs_cnt = trace_regs_cnt;
                f->regs = (StackFrameRegisterLocation **)loc_alloc(trace_regs_cnt * sizeof(StackFrameRegisterLocation *));
                memcpy(f->regs, trace_regs, trace_regs_cnt * sizeof(StackFrameRegisterLocation *));
            }
            if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
            if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
            if (!error && id2register_error) error = id2register_error;
        }
        clear_trap(&trap);
    }
    else {
        error = trap.error;
    }
    if (get_error_code(error) != ERR_INV_COMMAND) f->error = get_error_report(error);
    cache_notify(&f->cache);
    if (f->disposed) free_stack_frame_cache(f);
}

int get_next_stack_frame(StackFrame * frame, StackFrame * down) {
    Trap trap;
    unsigned h;
    LINK * l;
    uint64_t ip = 0;
    Context * ctx = frame->ctx;
    /* Here we assume that stack tracing info is valid for all threads in same memory space */
    Context * prs = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
    SymbolsCache * syms = NULL;
    StackFrameCache * f = NULL;

    if (!set_trap(&trap)) return -1;

    if (read_reg_value(frame, get_PC_definition(ctx), &ip) < 0) {
        if (frame->is_top_frame) exception(errno);
        clear_trap(&trap);
        return 0;
    }

    h = hash_frame(prs);
    syms = get_symbols_cache();
    for (l = syms->link_frame[h].next; l != syms->link_frame + h; l = l->next) {
        StackFrameCache * c = syms2frame(l);
        if (c->ctx == prs) {
            if (c->pending != NULL) {
                cache_wait(&c->cache);
            }
            else if (c->address <= ip && c->address + c->size > ip) {
                f = c;
                break;
            }
        }
    }

    assert(f == NULL || f->pending == NULL);

    if (f == NULL && !syms->service_available) {
        /* nothing */
    }
    else if (f == NULL) {
        Channel * c = get_channel(syms);
        f = (StackFrameCache *)loc_alloc_zero(sizeof(StackFrameCache));
        list_add_first(&f->link_syms, syms->link_frame + h);
        context_lock(f->ctx = prs);
        f->ip = ip;
        f->pending = protocol_send_command(c, SYMBOLS, "findFrameInfo", validate_frame, f);
        json_write_string(&c->out, f->ctx->id);
        write_stream(&c->out, 0);
        json_write_uint64(&c->out, ip);
        write_stream(&c->out, 0);
        write_stream(&c->out, MARKER_EOM);
        cache_wait(&f->cache);
    }
    else if (f->error != NULL) {
        exception(set_error_report_errno(f->error));
    }
    else if (f->fp != NULL) {
        Trap trap;
        if (set_trap(&trap)) {
            int i;
            LocationExpressionState * state;
            state = evaluate_location_expression(ctx, frame, f->fp->cmds, f->fp->cmds_cnt, NULL, 0);
            if (state->stk_pos != 1) str_exception(ERR_OTHER, "Invalid stack trace expression");
            frame->fp = (ContextAddress)state->stk[0];
            frame->is_walked = 1;
            for (i = 0; i < f->regs_cnt; i++) {
                int ok = 0;
                uint64_t v = 0;
                Trap trap_reg;
                if (set_trap(&trap_reg)) {
                    /* If a saved register value cannot be evaluated - ignore it */
                    state = evaluate_location_expression(ctx, frame, f->regs[i]->cmds, f->regs[i]->cmds_cnt, NULL, 0);
                    if (state->stk_pos == 1) {
                        v = state->stk[0];
                        ok = 1;
                    }
                    clear_trap(&trap_reg);
                }
                if (ok && write_reg_value(down, f->regs[i]->reg, v) < 0) exception(errno);
            }
            clear_trap(&trap);
        }
        else {
            frame->fp = 0;
        }
    }

    clear_trap(&trap);
    return 0;
}

int get_funccall_info(const Symbol * func,
        const Symbol ** args, unsigned args_cnt, FunctionCallInfo ** info) {
    /* TODO: get_funccall_info() in symbols proxy */
    set_errno(ERR_OTHER, "get_funccall_info() is not supported yet by TCF server");
    return -1;
}

const char * get_symbol_file_name(MemoryRegion * module) {
    errno = 0;
    return NULL;
}

/*************************************************************************************************/

static void flush_syms(Context * ctx, int mode) {
    LINK * l;
    LINK * m;
    int i;

    for (m = root.next; m != &root; m = m->next) {
        SymbolsCache * syms = root2syms(m);
        for (i = 0; i < HASH_SIZE; i++) {
            l = syms->link_sym[i].next;
            while (l != syms->link_sym + i) {
                SymInfoCache * c = syms2sym(l);
                l = l->next;
                if (!c->done_context || c->error_get_context != NULL) {
                    free_sym_info_cache(c);
                }
                else if (c->update_owner == NULL || c->update_owner->exited) {
                    free_sym_info_cache(c);
                }
                else if ((mode & (1 << c->update_policy)) && ctx == c->update_owner) {
                    if (mode == (1 << UPDATE_ON_EXE_STATE_CHANGES)) {
                        c->degraded = 1;
                    }
                    else {
                        free_sym_info_cache(c);
                    }
                }
            }
            l = syms->link_find_by_name[i].next;
            while (l != syms->link_find_by_name + i) {
                FindSymCache * c = syms2find(l);
                l = l->next;
                if ((mode & (1 << c->update_policy)) && c->ctx == ctx) {
                    free_find_sym_cache(c);
                }
            }
            l = syms->link_find_in_scope[i].next;
            while (l != syms->link_find_in_scope + i) {
                FindSymCache * c = syms2find(l);
                l = l->next;
                if ((mode & (1 << c->update_policy)) && c->ctx == ctx) {
                    free_find_sym_cache(c);
                }
            }
            l = syms->link_list[i].next;
            while (l != syms->link_list + i) {
                FindSymCache * c = syms2find(l);
                l = l->next;
                if ((mode & (1 << c->update_policy)) && c->ctx == ctx) {
                    free_find_sym_cache(c);
                }
            }
            if (mode & (1 << UPDATE_ON_MEMORY_MAP_CHANGES)) {
                Context * prs = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
                l = syms->link_frame[i].next;
                while (l != syms->link_frame + i) {
                    StackFrameCache * c = syms2frame(l);
                    l = l->next;
                    if (c->ctx == prs) free_stack_frame_cache(c);
                }
                l = syms->link_location[i].next;
                while (l != syms->link_location + i) {
                    LocationInfoCache * c = syms2location(l);
                    l = l->next;
                    if (c->ctx == prs) free_location_info_cache(c);
                }
            }
        }
    }
}

static void event_context_created(Context * ctx, void * x) {
    flush_syms(ctx, ~0);
}

static void event_context_exited(Context * ctx, void * x) {
    flush_syms(ctx, ~0);
}

static void event_context_stopped(Context * ctx, void * x) {
    flush_syms(ctx, (1 << UPDATE_ON_EXE_STATE_CHANGES));
}

static void event_context_started(Context * ctx, void * x) {
    flush_syms(ctx, (1 << UPDATE_ON_EXE_STATE_CHANGES));
}

static void event_context_changed(Context * ctx, void * x) {
    flush_syms(ctx, (1 << UPDATE_ON_MEMORY_MAP_CHANGES) | (1 << UPDATE_ON_EXE_STATE_CHANGES));
}

static void channel_close_listener(Channel * c) {
    LINK * l = root.next;
    while (l != &root) {
        SymbolsCache * s = root2syms(l);
        l = l->next;
        if (s->channel == c) free_symbols_cache(s);
    }
}

void ini_symbols_lib(void) {
    static ContextEventListener listener = {
        event_context_created,
        event_context_exited,
        event_context_stopped,
        event_context_started,
        event_context_changed
    };
    add_context_event_listener(&listener, NULL);
    add_channel_close_listener(channel_close_listener);
}

#endif
