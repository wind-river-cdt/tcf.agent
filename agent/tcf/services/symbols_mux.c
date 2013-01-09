/*******************************************************************************
 * Copyright (c) 2012 Wind River Systems, Inc. and others.
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
 * Symbols Muliplexer - Provides a symbol multiplexer to support several
 * file format in the same TCF agent and in the same debug session.
 */

#include <tcf/config.h>

#if ENABLE_SymbolsMux && SERVICE_Symbols
#include <assert.h>
#include <stdio.h>
#include <tcf/services/symbols.h>
#include <tcf/services/symbols_mux.h>
#include <tcf/services/memorymap.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/context.h>
#include <tcf/services/stacktrace.h>

static SymbolReader ** readers = NULL;
static unsigned reader_cnt = 0;
static unsigned max_reader_cnt = 0;
static Context * find_symbol_ctx = NULL;
static Symbol ** find_symbol_list = NULL;

static int get_sym_addr(Context * ctx, int frame, ContextAddress addr,
        ContextAddress * sym_addr) {
    if (frame == STACK_NO_FRAME) *sym_addr = addr;
    else if (frame == STACK_TOP_FRAME) {
        if (!ctx->stopped) {
            errno = ERR_IS_RUNNING;
            return -1;
        }
        if (ctx->exited) {
            errno = ERR_ALREADY_EXITED;
            return -1;
        }
        *sym_addr = get_regs_PC(ctx);
    }
    else {
        uint64_t ip = 0;
        StackFrame * info = NULL;
        if (get_frame_info(ctx, frame, &info) < 0) return -1;
        if (read_reg_value(info, get_PC_definition(ctx), &ip) < 0) return -1;
        if (!info->is_top_frame && ip > 0) ip--;
        *sym_addr = (ContextAddress) ip;
    }
    return 0;
}

static int get_symbol_reader(Context * ctx, int frame, ContextAddress addr, SymbolReader ** sym_reader) {
    ContextAddress sym_addr;
    unsigned i;

    *sym_reader = NULL;
    if (reader_cnt == 1) {
        *sym_reader = readers[0];
        return 0;
    }
    if (get_sym_addr(ctx, frame, addr, &sym_addr) == -1) return -1;
    for (i = 0; i < reader_cnt; i++) {
        if (readers[i]->reader_is_valid(ctx, sym_addr)) {
            *sym_reader = readers[i];
            return 0;
        }
    }
    return 0;
}

int find_symbol_by_name(Context * ctx, int frame, ContextAddress ip, const char * name,
        Symbol ** res) {
    unsigned i;

    find_symbol_ctx = NULL;
    for (i = 0; i < reader_cnt; i++) find_symbol_list[i] = NULL;

    for (i = 0; i < reader_cnt; i++) {
        Symbol * sym;
        if (readers[i]->find_symbol_by_name(ctx, frame, ip, name, &sym) == 0) {
            find_symbol_list[i] = sym;
            assert(sym != NULL);
            if (find_symbol_ctx == NULL) {
                find_symbol_ctx = ctx;
                *res = sym;
            }
        }
        else if (errno != ERR_SYM_NOT_FOUND) return -1;
    }
    if (find_symbol_ctx != NULL) return 0;
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

int find_symbol_in_scope(Context * ctx, int frame, ContextAddress ip, Symbol * scope,
        const char * name, Symbol ** res) {
    unsigned i;
    SymbolReader * reader;

    for (i = 0; i < reader_cnt; i++) find_symbol_list[i] = NULL;
    find_symbol_ctx = NULL;

    if (get_symbol_reader(ctx, frame,ip,&reader) == -1) return -1;
    if (reader != NULL) {
        Symbol * sym = NULL;
        if (reader->find_symbol_in_scope(ctx, frame, ip, scope, name, &sym) == 0) {
            find_symbol_list[reader->reader_index] = sym;
            *res = sym;
            find_symbol_ctx = ctx;
            assert (sym != NULL);
            return 0;
        }
        else return -1;
    }
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

int find_symbol_by_addr(Context * ctx, int frame, ContextAddress addr, Symbol ** res) {
    unsigned i;
    SymbolReader * reader;

    for (i = 0; i < reader_cnt; i++) find_symbol_list[i] = NULL;
    find_symbol_ctx = NULL;

    if (get_symbol_reader(ctx, frame, addr, &reader) == -1) return -1;
    if (reader != NULL) {
        Symbol * sym;
        if (reader->find_symbol_by_addr(ctx, frame, addr, &sym) == 0) {
            find_symbol_list[reader->reader_index] = sym;
            *res = sym;
            assert (sym != NULL);
            find_symbol_ctx = ctx;
            return 0;
        }
        else return -1;
    }
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

int find_next_symbol(Symbol ** sym) {
    unsigned i;

    if (find_symbol_ctx == NULL) {
        errno = ERR_SYM_NOT_FOUND;
        return -1;
    }
    for (i = 0; i < reader_cnt; i++) {
        if (find_symbol_list[i] != NULL) {
            if (find_symbol_list[i] != *sym) {
                    *sym = find_symbol_list[i];
                return 0;
            }
            find_symbol_list[i] = NULL;
            if (readers[i]->find_next_symbol(sym) == 0) {
                find_symbol_list[i] = *sym;
                return 0;
            }
        }
    }
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

int enumerate_symbols(Context * ctx, int frame, EnumerateSymbolsCallBack * call_back, void * args) {
    SymbolReader * reader = NULL;
    if (get_symbol_reader(ctx, frame, 0, &reader) == -1) return 0;
    if (reader) return reader->enumerate_symbols(ctx, frame, call_back, args);
    return 0;
}

const char * symbol2id(const Symbol * sym) {
    SymbolReader * reader = *(SymbolReader **)sym;
    static char buf[256];
    const char * id;
    assert (reader != NULL);
    id = reader->symbol2id(sym);
    if (id) {
        buf[0] = '@';
        buf[1] = 'M';
        buf[2] = (uint8_t)reader->reader_index + '0';
        buf[3] = '.';
        strcpy(&buf[4], id);
        return buf;
    }
    return id;
}

int id2symbol(const char * id, Symbol ** res) {
    unsigned reader_index;
    if (id != NULL && id[0] == '@' && id[1] == 'M' && id[3] == '.') {
        reader_index = id[2] - '0';
        assert (reader_index < reader_cnt);
        return (readers[reader_index]->id2symbol(id + 4, res));
    }
    errno = ERR_INV_CONTEXT;
    return -1;
}

ContextAddress is_plt_section(Context * ctx, ContextAddress addr) {
    SymbolReader * reader = NULL;
    if (get_symbol_reader(ctx, STACK_NO_FRAME, addr, &reader) == -1) return 0;
    if (reader) return reader->is_plt_section(ctx, addr);
    return 0;
}

int get_stack_tracing_info(Context * ctx, ContextAddress rt_addr, StackTracingInfo ** info) {
    SymbolReader * reader = NULL;
    *info  = NULL;
    if (get_symbol_reader(ctx, STACK_NO_FRAME, rt_addr, &reader) == -1) return 0;
    if (reader) return reader->get_stack_tracing_info(ctx, rt_addr, info);
    return 0;
}

const char * get_symbol_file_name(Context * ctx, MemoryRegion * module) {
    unsigned i;
    const char * name;
    for (i = 0; i < reader_cnt; i++) {
        name = readers[i]->get_symbol_file_name(ctx, module);
        if (name != NULL) {
            if (module == NULL) return name;
            if (name != module->file_name) return name;
        }
    }
    if (module == NULL) return NULL;
    else return module->file_name;
}

int get_symbol_class(const Symbol * sym, int * sym_class) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_class(sym, sym_class);
}

int get_symbol_type(const Symbol * sym, Symbol ** type) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_type(sym, type);
}

int get_symbol_type_class(const Symbol * sym, int * type_class) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_type_class(sym, type_class);
}

int get_symbol_update_policy(const Symbol * sym, char ** id, int * policy) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_update_policy(sym, id, policy);
}

int get_symbol_name(const Symbol * sym, char ** name) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_name(sym, name);
}

int get_symbol_size(const Symbol * sym, ContextAddress * size) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_size(sym, size);
}

int get_symbol_base_type(const Symbol * sym, Symbol ** base_type) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_base_type(sym, base_type);
}

int get_symbol_index_type(const Symbol * sym, Symbol ** index_type) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_index_type(sym, index_type);
}

int get_symbol_container(const Symbol * sym, Symbol ** container) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_container(sym, container);
}

int get_symbol_length(const Symbol * sym, ContextAddress * length) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_length(sym, length);
}

int get_symbol_lower_bound(const Symbol * sym, int64_t * value) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_lower_bound(sym, value);

}

int get_symbol_children(const Symbol * sym, Symbol *** children, int * count) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_children(sym, children, count);
}

int get_array_symbol(const Symbol * sym, ContextAddress length, Symbol ** ptr) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_array_symbol(sym, length, ptr);
}

int get_location_info(const Symbol * sym, LocationInfo ** res) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_location_info(sym, res);
}

int get_symbol_flags(const Symbol * sym, SYM_FLAGS * flags) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_flags(sym, flags);
}

int get_symbol_frame(const Symbol * sym, Context ** ctx, int * frame) {
    SymbolReader * reader = *(SymbolReader **) sym;
    assert(reader != NULL);
    return reader->get_symbol_frame(sym, ctx, frame);
}

int get_funccall_info(const Symbol * func, const Symbol ** args, unsigned args_cnt,
        FunctionCallInfo ** res) {
    SymbolReader * reader = *(SymbolReader **) func;
    assert(reader != NULL);
    return reader->get_funccall_info(func, args, args_cnt, res);
}

int get_context_isa(Context * ctx, ContextAddress ip, const char ** isa,
        ContextAddress * range_addr, ContextAddress * range_size) {
    SymbolReader * reader = NULL;
    *isa = NULL;
    *range_addr = ip;
    *range_size = 1;

    if (get_symbol_reader(ctx, STACK_NO_FRAME, ip, &reader) == -1) return 0;
    if (reader != NULL) return reader->get_context_isa(ctx, ip, isa, range_addr, range_size);
    return 0;
}

int add_symbols_reader(SymbolReader * reader) {
    unsigned i;
    if (reader_cnt >= max_reader_cnt) {
        max_reader_cnt += 2;
        readers = (SymbolReader **)loc_realloc(readers, max_reader_cnt * sizeof(reader));
        find_symbol_list = (Symbol **) loc_realloc(find_symbol_list, max_reader_cnt * sizeof(Symbol *));
    }
    readers[reader_cnt] = reader;
    reader->reader_index = reader_cnt;
    reader_cnt++;
    for (i = 0; i < reader_cnt; i++) find_symbol_list[i] = NULL;
    find_symbol_ctx = NULL;
    return 0;
}

void ini_symbols_lib(void) {
    /*
     * We keep this to limit the impact of changes. In the ideal world, those
     * initialization routines should be called from the agent initialization code.
     */
#if ENABLE_PE
    win32_reader_ini_symbols_lib();
#endif
#if ENABLE_ELF
    elf_reader_ini_symbols_lib();
#endif
}
#endif /* Enable_SymbolsMux && SERVICE_Symbols */
