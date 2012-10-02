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
 * This module implements specific ELF symbol's API
 */

#include <tcf/config.h>

#if SERVICE_Symbols && !ENABLE_SymbolsProxy && ENABLE_ELF

#include <assert.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/elf-symbols.h>

struct EnumerateSymbols {
    int64_t mtime;
    ino_t ino;
    dev_t dev;
    uint32_t batch_idx;
    uint32_t sec_idx;
    char file_name[FILE_PATH_SIZE];
    char ctxId[256];
};

static int enumerate_symbol_table (ELF_Section * sec, EnumerateSymbols * enum_syms, EnumerateBatchSymbolsCallBack * call_back, void * args) {
    uint32_t sym_idx;
    int cont = 1;
    int has_more = 0;

    for (sym_idx = enum_syms->batch_idx; cont == 1 && sym_idx < sec->sym_count; sym_idx++) {
        ELF_SymbolInfo sym_info;
        Symbol * sym;

        unpack_elf_symbol_info(sec, sym_idx, &sym_info);

        if (elf_tcf_symbol (&sym_info, &sym) < 0) exception (errno);

        cont = call_back (args, sym);
    }
    enum_syms->batch_idx = sym_idx;
    if (sym_idx < sec->sym_count && cont != -1) has_more = 1;
    return has_more;
}

int elf_enumerate_symbols (Context * ctx, const char * file_name, EnumerateSymbols ** enum_syms, EnumerateBatchSymbolsCallBack * call_back, void * args) {
    Trap trap;
    ELF_File * file;
    unsigned sec_idx;
    int has_more = 0;

    if (!set_trap(&trap)) {
        loc_free (*enum_syms);
        *enum_syms = NULL;
        return -1;
    }

    if (ctx == NULL && file_name == NULL) {
        assert (*enum_syms != NULL);

        file = elf_open ((*enum_syms)->file_name);
        if (file == NULL) exception (errno);

        /*
         * Check that the file is identical to the initial file and the context
         * still exists.
         */

        if (file->ino != (*enum_syms)->ino || file->dev != (*enum_syms)->dev || file->mtime != (*enum_syms)->mtime) {
            str_exception(ERR_OTHER, "The elf symbol file has changed");
        }
        else {
            ctx = id2ctx((*enum_syms)->ctxId);
            if (ctx == NULL) exception (ERR_INV_CONTEXT);
            else if (ctx->exited) exception (ERR_ALREADY_EXITED);
        }
        sec_idx = (*enum_syms)->sec_idx;
    }
    else {
        unsigned symtab_idx = 0;
        unsigned dynsym_idx = 0;
        unsigned ix;

        assert (file_name != NULL && enum_syms != NULL && *enum_syms == NULL);

        file = elf_open (file_name);
        if (file == NULL) exception (errno);

        if (file->sections == NULL) str_exception(ERR_OTHER, "The file does not have sections");

        /* Look for the symbol table sections */

        for (ix = 0; ix < file->section_cnt && symtab_idx == 0 && dynsym_idx == 0; ix++) {
            ELF_Section * sec = file->sections + ix;
            if (sec->type == SHT_SYMTAB) symtab_idx = ix;
            else if (sec->type == SHT_DYNSYM) dynsym_idx = ix;
        }

        if (symtab_idx == 0 && dynsym_idx == 0) str_exception(ERR_OTHER, "The file does not have a symbol table");

       /* Set priority to the symbol table */

        if (symtab_idx != 0) sec_idx = symtab_idx;
        else sec_idx = dynsym_idx;

        *enum_syms = (EnumerateSymbols *)loc_alloc_zero (sizeof (EnumerateSymbols));
        strlcpy ((*enum_syms)->file_name, file_name, sizeof ((*enum_syms)->file_name));
        if (strlen (file_name) != strlen ((*enum_syms)->file_name)) str_exception (ERR_OTHER, "File pathname too long");

        strlcpy ((*enum_syms)->ctxId, ctx->id, sizeof ((*enum_syms)->ctxId));
        (*enum_syms)->dev = file->dev;
        (*enum_syms)->ino = file->ino;
        (*enum_syms)->mtime = file->mtime;
        (*enum_syms)->sec_idx = sec_idx;
    }

    has_more = enumerate_symbol_table(file->sections + sec_idx, *enum_syms, call_back, args);

    clear_trap(&trap);

    if (has_more == 0) {
        loc_free (*enum_syms);
        *enum_syms = NULL;
    }

    return has_more;
}

#endif
