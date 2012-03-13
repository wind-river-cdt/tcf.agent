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
 * Symbols service - ELF version.
 */

#include <tcf/config.h>

#if SERVICE_Symbols && !ENABLE_SymbolsProxy && ENABLE_ELF

#if defined(_WRS_KERNEL)
#  include <symLib.h>
#  include <sysSymTbl.h>
#endif

#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/events.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/tcf_elf.h>
#include <tcf/services/dwarf.h>
#include <tcf/services/dwarfcache.h>
#include <tcf/services/dwarfexpr.h>
#include <tcf/services/dwarfecomp.h>
#include <tcf/services/dwarfframe.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/funccall.h>
#include <tcf/services/symbols.h>
#include <tcf/services/vm.h>
#if ENABLE_RCBP_TEST
#  include <tcf/main/test.h>
#endif

struct Symbol {
    unsigned magic;
    ObjectInfo * obj;
    ObjectInfo * var; /* 'this' object if the symbol represents implicit 'this' reference */
    ELF_Section * tbl;
    int has_size;
    int has_address;
    ContextAddress size;
    ContextAddress address;
    int sym_class;
    Context * ctx;
    int frame;
    unsigned index;
    unsigned dimension;
    unsigned cardinal;
    ContextAddress length;
    Symbol * base;
};

#define is_array_type_pseudo_symbol(s) (s->sym_class == SYM_CLASS_TYPE && s->obj == NULL && s->base != NULL)
#define is_cardinal_type_pseudo_symbol(s) (s->sym_class == SYM_CLASS_TYPE && s->obj == NULL && s->base == NULL)
#define is_constant_pseudo_symbol(s) (s->sym_class == SYM_CLASS_VALUE && s->obj == NULL && s->base != NULL)

static Context * sym_ctx;
static int sym_frame;
static ContextAddress sym_ip;

typedef long ConstantValueType;

static struct ConstantPseudoSymbol {
    const char * name;
    const char * type;
    ConstantValueType value;
} constant_pseudo_symbols[] = {
    { "false", "bool", 0 },
    { "true", "bool", 1 },
    { NULL, NULL, 0 },
};

static struct BaseTypeAlias {
    const char * name;
    const char * alias;
} base_types_aliases[] = {
    { "int", "signed int" },
    { "signed", "int" },
    { "signed int", "int" },
    { "unsigned", "unsigned int" },
    { "short", "short int" },
    { "signed short", "short int" },
    { "signed short int", "short int" },
    { "unsigned short", "unsigned short int" },
    { "long", "long int" },
    { "signed long", "long int" },
    { "signed long int", "long int" },
    { "unsigned long", "unsigned long int" },
    { "long long", "long long int" },
    { "signed long long", "long long int" },
    { "signed long long int", "long long int" },
    { "unsigned long long", "unsigned long long int" },
    { "char", "signed char" },
    { "char", "unsigned char" },
    { NULL, NULL }
};

static Symbol ** find_symbol_buf = NULL;
static unsigned find_symbol_pos = 0;
static unsigned find_symbol_cnt = 0;
static unsigned find_symbol_max = 0;

#define SYMBOL_MAGIC 0x34875234

/* This function is used for DWARF testing */
extern ObjectInfo * get_symbol_object(Symbol * sym);
ObjectInfo * get_symbol_object(Symbol * sym) {
    return sym->obj;
}

static Symbol * alloc_symbol(void) {
    Symbol * s = (Symbol *)tmp_alloc_zero(sizeof(Symbol));
    s->magic = SYMBOL_MAGIC;
    return s;
}

static int get_sym_context(Context * ctx, int frame, ContextAddress addr) {
    if (frame == STACK_NO_FRAME) {
        ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
        sym_ip = addr;
    }
    else if (frame == STACK_TOP_FRAME) {
        if (!ctx->stopped) {
            errno = ERR_IS_RUNNING;
            return -1;
        }
        if (ctx->exited) {
            errno = ERR_ALREADY_EXITED;
            return -1;
        }
        sym_ip = get_regs_PC(ctx);
    }
    else {
        U8_T ip = 0;
        StackFrame * info = NULL;
        if (get_frame_info(ctx, frame, &info) < 0) return -1;
        if (read_reg_value(info, get_PC_definition(ctx), &ip) < 0) return -1;
        sym_ip = (ContextAddress)ip;
    }
    sym_ctx = ctx;
    sym_frame = frame;
    return 0;
}

/* Map ELF symbol table entry value to run-time address in given context address space */
static int syminfo2address(Context * ctx, ELF_SymbolInfo * info, ContextAddress * address) {
    switch (info->type) {
    case STT_OBJECT:
    case STT_FUNC:
        {
            U8_T value = info->value;
            ELF_File * file = info->sym_section->file;
            ELF_Section * sec = NULL;
            if (info->section_index == SHN_UNDEF) {
                set_errno(ERR_OTHER, "Cannot get address of ELF symbol: the symbol is undefined");
                return -1;
            }
            if (info->section_index == SHN_ABS) {
                *address = (ContextAddress)value;
                return 0;
            }
            if (info->section_index == SHN_COMMON) {
                set_errno(ERR_OTHER, "Cannot get address of ELF symbol: the symbol is a common block");
                return -1;
            }
            if (file->type == ET_REL && info->section != NULL) {
                sec = info->section;
                value += sec->addr;
            }
            *address = elf_map_to_run_time_address(ctx, file, sec, (ContextAddress)value);
            return errno ? -1 : 0;
        }
    }
    set_errno(ERR_OTHER, "Cannot get address of ELF symbol: wrong symbol type");
    return -1;
}

/* Return 1 if evaluation of symbol properties requires a stack frame.
 * Return 0 otherwise.
 * In case of a doubt, should return 1. */
static int is_frame_based_object(Symbol * sym) {
    int res = 0;

    if (sym->var != NULL) return 1;

    switch (sym->sym_class) {
    case SYM_CLASS_VALUE:
    case SYM_CLASS_BLOCK:
    case SYM_CLASS_NAMESPACE:
    case SYM_CLASS_COMP_UNIT:
    case SYM_CLASS_FUNCTION:
        return 0;
    case SYM_CLASS_TYPE:
        if (sym->obj != NULL) {
            ObjectInfo * obj = sym->obj;
            while (1) {
                switch (obj->mTag) {
                case TAG_typedef:
                case TAG_packed_type:
                case TAG_const_type:
                case TAG_volatile_type:
                case TAG_restrict_type:
                case TAG_shared_type:
                    if (obj->mType == NULL) break;
                    obj = obj->mType;
                    continue;
                case TAG_base_type:
                case TAG_fund_type:
                case TAG_class_type:
                case TAG_union_type:
                case TAG_structure_type:
                case TAG_enumeration_type:
                case TAG_subroutine_type:
                case TAG_pointer_type:
                case TAG_reference_type:
                case TAG_ptr_to_member_type:
                    return 0;
                }
                break;
            }
        }
        break;
    }

    if (sym->obj != NULL) {
        ContextAddress addr = 0;
        ContextAddress size = 0;
        Context * org_ctx = sym_ctx;
        int org_frame = sym_frame;
        ContextAddress org_ip = sym_ip;

        if (sym->sym_class == SYM_CLASS_REFERENCE) {
            if (sym->obj->mTag == TAG_member || sym->obj->mTag == TAG_inheritance) {
                if (get_symbol_offset(sym, &addr) < 0) res = 1;
            }
            else if (get_symbol_address(sym, &addr) < 0) {
                res = 1;
            }
            else {
                sym->has_address = 1;
                sym->address = addr;
            }
        }

        if (!res) {
            if (get_symbol_size(sym, &size) < 0) {
                res = 1;
            }
            else {
                sym->has_size = 1;
                sym->size = size;
            }
        }

        sym_ctx = org_ctx;
        sym_frame = org_frame;
        sym_ip = org_ip;
    }

    return res;
}

static void object2symbol(ObjectInfo * obj, Symbol ** res) {
    Symbol * sym = alloc_symbol();
    sym->obj = obj;
    switch (obj->mTag) {
    case TAG_global_subroutine:
    case TAG_inlined_subroutine:
    case TAG_subroutine:
    case TAG_subprogram:
    case TAG_entry_point:
        sym->sym_class = SYM_CLASS_FUNCTION;
        break;
    case TAG_array_type:
    case TAG_class_type:
    case TAG_enumeration_type:
    case TAG_pointer_type:
    case TAG_reference_type:
    case TAG_mod_pointer:
    case TAG_mod_reference:
    case TAG_string_type:
    case TAG_structure_type:
    case TAG_subroutine_type:
    case TAG_union_type:
    case TAG_ptr_to_member_type:
    case TAG_set_type:
    case TAG_subrange_type:
    case TAG_base_type:
    case TAG_fund_type:
    case TAG_file_type:
    case TAG_packed_type:
    case TAG_thrown_type:
    case TAG_const_type:
    case TAG_volatile_type:
    case TAG_restrict_type:
    case TAG_interface_type:
    case TAG_unspecified_type:
    case TAG_mutable_type:
    case TAG_shared_type:
    case TAG_typedef:
    case TAG_template_type_param:
        sym->sym_class = SYM_CLASS_TYPE;
        break;
    case TAG_global_variable:
    case TAG_inheritance:
    case TAG_member:
    case TAG_formal_parameter:
    case TAG_unspecified_parameters:
    case TAG_local_variable:
    case TAG_variable:
        sym->sym_class = SYM_CLASS_REFERENCE;
        break;
    case TAG_constant:
    case TAG_enumerator:
        sym->sym_class = SYM_CLASS_VALUE;
        break;
    case TAG_compile_unit:
    case TAG_partial_unit:
        sym->sym_class = SYM_CLASS_COMP_UNIT;
        break;
    case TAG_lexical_block:
    case TAG_with_stmt:
    case TAG_try_block:
    case TAG_catch_block:
        sym->sym_class = SYM_CLASS_BLOCK;
        break;
    case TAG_namespace:
        sym->sym_class = SYM_CLASS_NAMESPACE;
        break;
    }
    sym->frame = STACK_NO_FRAME;
    sym->ctx = context_get_group(sym_ctx, CONTEXT_GROUP_SYMBOLS);
    if (sym_frame != STACK_NO_FRAME && is_frame_based_object(sym)) {
        sym->frame = sym_frame;
        sym->ctx = sym_ctx;
    }
    *res = sym;
}

static ObjectInfo * get_object_type(ObjectInfo * obj) {
    if (obj != NULL) {
        switch (obj->mTag) {
        case TAG_global_subroutine:
        case TAG_inlined_subroutine:
        case TAG_subroutine:
        case TAG_subprogram:
        case TAG_entry_point:
        case TAG_enumerator:
        case TAG_formal_parameter:
        case TAG_unspecified_parameters:
        case TAG_global_variable:
        case TAG_local_variable:
        case TAG_variable:
        case TAG_inheritance:
        case TAG_member:
        case TAG_constant:
            obj = obj->mType;
            break;
        }
    }
    return obj;
}

static int is_modified_type(ObjectInfo * obj) {
    if (obj != NULL) {
        switch (obj->mTag) {
        case TAG_subrange_type:
        case TAG_packed_type:
        case TAG_const_type:
        case TAG_volatile_type:
        case TAG_restrict_type:
        case TAG_shared_type:
        case TAG_typedef:
        case TAG_template_type_param:
            return 1;
        }
    }
    return 0;
}

/* Get object original type, skipping typedefs and all modifications like const, volatile, etc. */
static ObjectInfo * get_original_type(ObjectInfo * obj) {
    obj = get_object_type(obj);
    while (obj != NULL && obj->mType != NULL && is_modified_type(obj)) obj = obj->mType;
    return obj;
}

static int get_num_prop(ObjectInfo * obj, U2_T at, U8_T * res) {
    Trap trap;
    PropertyValue v;

    if (!set_trap(&trap)) return 0;
    read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, at, &v);
    *res = get_numeric_property_value(&v);
    clear_trap(&trap);
    return 1;
}

/* Check run-time 'addr' belongs to an object address range(s) */
static int check_in_range(ObjectInfo * obj, ContextAddress rt_offs, ContextAddress addr) {
    if (obj->mFlags & DOIF_ranges) {
        Trap trap;
        if (set_trap(&trap)) {
            CompUnit * unit = obj->mCompUnit;
            DWARFCache * cache = get_dwarf_cache(unit->mFile);
            ELF_Section * debug_ranges = cache->mDebugRanges;
            if (debug_ranges != NULL) {
                ContextAddress lt_addr = addr - rt_offs;
                ContextAddress base = unit->mObject->u.mCode.mLowPC;
                int res = 0;

                dio_EnterSection(&unit->mDesc, debug_ranges, obj->u.mCode.mHighPC.mRanges);
                for (;;) {
                    ELF_Section * sec = NULL;
                    U8_T x = dio_ReadAddress(&sec);
                    U8_T y = dio_ReadAddress(&sec);
                    if (x == 0 && y == 0) break;
                    if (x == ((U8_T)1 << unit->mDesc.mAddressSize * 8) - 1) {
                        base = (ContextAddress)y;
                    }
                    else {
                        x = base + x;
                        y = base + y;
                        if (x <= lt_addr && lt_addr < y) {
                            res = 1;
                            break;
                        }
                    }
                }
                dio_ExitSection();
                clear_trap(&trap);
                return res;
            }
            clear_trap(&trap);
        }
        return 0;
    }

    if (obj->u.mCode.mHighPC.mAddr > obj->u.mCode.mLowPC) {
        ContextAddress lt_addr = addr - rt_offs;
        return lt_addr >= obj->u.mCode.mLowPC && lt_addr < obj->u.mCode.mHighPC.mAddr;
    }

    return 0;
}

static void add_to_find_symbol_buf(ObjectInfo * obj) {
    unsigned n = 0;
    while (n < find_symbol_cnt) {
        if (find_symbol_buf[n++]->obj == obj) return;
    }
    if (find_symbol_cnt >= find_symbol_max) {
        find_symbol_max += 32;
        find_symbol_buf = (Symbol **)loc_realloc(find_symbol_buf, sizeof(Symbol *) * find_symbol_max);
    }
    object2symbol(obj, find_symbol_buf + find_symbol_cnt++);
}

static int check_obj_name(ObjectInfo * obj, const char * n) {
    const char * s = obj->mName;
    if (s == NULL) return 0;
    return cmp_symbol_names(s, n) == 0;
}

static int find_by_name_in_pub_names(DWARFCache * cache, const char * name, Symbol ** sym) {
    PubNamesTable * tbl = &cache->mPubNames;
    if (tbl->mHash != NULL) {
        ObjectInfo * decl = NULL;
        ObjectInfo * type = NULL;
        ObjectInfo * other = NULL;
        unsigned n = tbl->mHash[calc_symbol_name_hash(name) % tbl->mHashSize];
        while (n != 0) {
            ObjectInfo * obj = tbl->mNext[n].mObject;
            if (check_obj_name(obj, name)) {
                if (obj->mFlags & DOIF_external) {
                    object2symbol(obj, sym);
                    return 1;
                }
                else if (obj->mFlags & DOIF_declaration) {
                    decl = obj;
                }
                else {
                    switch (obj->mTag) {
                    case TAG_class_type:
                    case TAG_structure_type:
                    case TAG_union_type:
                    case TAG_enumeration_type:
                        type = obj;
                        break;
                    default:
                        other = obj;
                        break;
                    }
                }
            }
            n = tbl->mNext[n].mNext;
        }
        if (other != NULL) {
            object2symbol(other, sym);
            return 1;
        }
        if (type != NULL) {
            object2symbol(type, sym);
            return 1;
        }
        if (decl != NULL) {
            object2symbol(decl, sym);
            return 1;
        }
    }
    return 0;
}

/* If 'decl' represents a declaration, replace it with definition - if possible */
static ObjectInfo * find_definition(ObjectInfo * decl) {
    if (decl == NULL) return NULL;
    if ((decl->mFlags & DOIF_declaration) == 0) return decl;
    if (decl->mDefinition != NULL) return decl->mDefinition;
    switch (decl->mTag) {
    case TAG_structure_type:
    case TAG_interface_type:
    case TAG_union_type:
    case TAG_class_type:
        if (get_dwarf_children(decl) != NULL) return decl;
    }
    if ((decl->mFlags & DOIF_external) != 0 && decl->mName != NULL) {
        int found = 0;
        Symbol * sym = NULL;
        DWARFCache * cache = get_dwarf_cache(get_dwarf_file(decl->mCompUnit->mFile));
        found = find_by_name_in_pub_names(cache, decl->mName, &sym);
        if (found && sym->obj != NULL &&
            sym->obj->mTag == decl->mTag &&
            (sym->obj->mFlags & DOIF_declaration) == 0) return sym->obj;
    }
    return decl;
}

static void find_in_object_tree(ObjectInfo * parent, ContextAddress rt_offs, ContextAddress ip, const char * name) {
    ObjectInfo * children = get_dwarf_children(parent);
    ObjectInfo * obj = NULL;
    ObjectInfo * sym_this = NULL;
    int obj_ptr_chk = 0;
    U8_T obj_ptr_id = 0;

    if (ip != 0) {
        /* Search nested blocks first */
        obj = children;
        while (obj != NULL) {
            switch (obj->mTag) {
            case TAG_compile_unit:
            case TAG_partial_unit:
            case TAG_module:
            case TAG_global_subroutine:
            case TAG_inlined_subroutine:
            case TAG_lexical_block:
            case TAG_with_stmt:
            case TAG_try_block:
            case TAG_catch_block:
            case TAG_subroutine:
            case TAG_subprogram:
                if (!check_in_range(obj, rt_offs, ip)) break;
                find_in_object_tree(obj, rt_offs, ip, name);
                break;
            }
            obj = obj->mSibling;
        }
    }

    /* Search current scope */
    obj = children;
    while (obj != NULL) {
        if ((obj->mFlags & DOIF_specification) == 0 && check_obj_name(obj, name)) {
            add_to_find_symbol_buf(find_definition(obj));
        }
        if (parent->mTag == TAG_subprogram && ip != 0) {
            if (!obj_ptr_chk) {
                get_num_prop(parent, AT_object_pointer, &obj_ptr_id);
                obj_ptr_chk = 1;
            }
            if (obj->mID == obj_ptr_id || (obj_ptr_id == 0 && obj->mTag == TAG_formal_parameter &&
                (obj->mFlags & DOIF_artificial) && obj->mName != NULL && strcmp(obj->mName, "this") == 0)) {
                sym_this = obj;
            }
        }
        obj = obj->mSibling;
    }

    if (sym_this != NULL) {
        /* Search in 'this' pointer */
        ObjectInfo * type = get_original_type(sym_this);
        if ((type->mTag == TAG_pointer_type || type->mTag == TAG_mod_pointer) && type->mType != NULL) {
            unsigned n = find_symbol_cnt;
            type = get_original_type(type->mType);
            find_in_object_tree(type, 0, 0, name);
            while (n < find_symbol_cnt) {
                Symbol * s = find_symbol_buf[n++];
                s->ctx = sym_ctx;
                s->frame = sym_frame;
                s->var = sym_this;
            }
        }
    }

    if (parent->mFlags & DOIF_extension) {
        /* If the parent is namespace extension, search in base namespace */
        PropertyValue p;
        ObjectInfo * name_space;
        read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, parent, AT_extension, &p);
        name_space = find_object(get_dwarf_cache(obj->mCompUnit->mFile), (ContextAddress)p.mValue);
        if (name_space != NULL) find_in_object_tree(name_space, 0, 0, name);
    }

    /* Search imported and inherited objects */
    obj = children;
    while (obj != NULL) {
        switch (obj->mTag) {
        case TAG_enumeration_type:
            find_in_object_tree(obj, 0, 0, name);
            break;
        case TAG_inheritance:
            find_in_object_tree(obj->mType, 0, 0, name);
            break;
        case TAG_imported_declaration:
            if (check_obj_name(obj, name)) {
                PropertyValue p;
                ObjectInfo * decl;
                read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_import, &p);
                decl = find_object(get_dwarf_cache(obj->mCompUnit->mFile), (ContextAddress)p.mValue);
                if (decl != NULL) {
                    if (obj->mName != NULL || check_obj_name(decl, name)) {
                        add_to_find_symbol_buf(find_definition(decl));
                    }
                }
            }
            break;
        case TAG_imported_module:
            find_in_object_tree(obj, 0, 0, name);
            {
                PropertyValue p;
                ObjectInfo * module;
                read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_import, &p);
                module = find_object(get_dwarf_cache(obj->mCompUnit->mFile), (ContextAddress)p.mValue);
                if (module != NULL && (module->mFlags & DOIF_find_mark) == 0) {
                    Trap trap;
                    if (set_trap(&trap)) {
                        module->mFlags |= DOIF_find_mark;
                        find_in_object_tree(module, 0, 0, name);
                        clear_trap(&trap);
                        module->mFlags &= ~DOIF_find_mark;
                    }
                    else {
                        module->mFlags &= ~DOIF_find_mark;
                        exception(trap.error);
                    }
                }
            }
            break;
        }
        obj = obj->mSibling;
    }
}

static int find_in_dwarf(const char * name, Symbol ** sym) {
    ContextAddress rt_addr = 0;
    UnitAddressRange * range = elf_find_unit(sym_ctx, sym_ip, sym_ip, &rt_addr);
    assert(find_symbol_pos == 0);
    assert(find_symbol_cnt == 0);
    if (range != NULL) {
        CompUnit * unit = range->mUnit;
        find_in_object_tree(unit->mObject, rt_addr - range->mAddr, sym_ip, name);
        if (unit->mBaseTypes != NULL) find_in_object_tree(unit->mBaseTypes->mObject, 0, 0, name);
    }
    if (find_symbol_cnt == 0) return 0;
    *sym = find_symbol_buf[find_symbol_pos++];
    return 1;
}

static void create_symbol_names_hash(ELF_Section * tbl) {
    unsigned i;
    unsigned sym_size = tbl->file->elf64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
    unsigned sym_cnt = (unsigned)(tbl->size / sym_size);
    tbl->sym_names_hash_size = sym_cnt;
    tbl->sym_names_hash = (unsigned *)loc_alloc_zero(sym_cnt * sizeof(unsigned));
    tbl->sym_names_next = (unsigned *)loc_alloc_zero(sym_cnt * sizeof(unsigned));
    for (i = 0; i < sym_cnt; i++) {
        ELF_SymbolInfo sym;
        unpack_elf_symbol_info(tbl, i, &sym);
        if (sym.bind == STB_GLOBAL && sym.name != NULL && sym.section_index != SHN_UNDEF) {
            unsigned h = calc_symbol_name_hash(sym.name) % sym_cnt;
            tbl->sym_names_next[i] = tbl->sym_names_hash[h];
            tbl->sym_names_hash[h] = i;
        }
    }
}

static int find_by_name_in_sym_table(DWARFCache * cache, const char * name, Symbol ** res) {
    unsigned m = 0;
    unsigned h = calc_symbol_name_hash(name);
    unsigned cnt = 0;
    Context * prs = context_get_group(sym_ctx, CONTEXT_GROUP_SYMBOLS);
    for (m = 1; m < cache->mFile->section_cnt; m++) {
        unsigned n;
        ELF_Section * tbl = cache->mFile->sections + m;
        if (tbl->sym_count == 0) continue;
        if (tbl->sym_names_hash == NULL) create_symbol_names_hash(tbl);
        n = tbl->sym_names_hash[h % tbl->sym_names_hash_size];
        while (n) {
            ELF_SymbolInfo sym_info;
            unpack_elf_symbol_info(tbl, n, &sym_info);
            if (cmp_symbol_names(name, sym_info.name) == 0) {
                int found = 0;
                ContextAddress addr = 0;
                if (sym_info.section_index != SHN_ABS && syminfo2address(prs, &sym_info, &addr) == 0) {
                    UnitAddressRange * range = elf_find_unit(sym_ctx, addr, addr, NULL);
                    if (range != NULL) {
                        ObjectInfo * obj = get_dwarf_children(range->mUnit->mObject);
                        while (obj != NULL) {
                            switch (obj->mTag) {
                            case TAG_global_subroutine:
                            case TAG_global_variable:
                            case TAG_subroutine:
                            case TAG_subprogram:
                            case TAG_variable:
                                if ((obj->mFlags & DOIF_external) != 0 && check_obj_name(obj, name)) {
                                    object2symbol(obj, res);
                                    found = 1;
                                    cnt++;
                                }
                                break;
                            }
                            obj = obj->mSibling;
                        }
                    }
                }
                if (!found) {
                    Symbol * sym = alloc_symbol();
                    sym->frame = STACK_NO_FRAME;
                    sym->ctx = prs;
                    sym->tbl = tbl;
                    sym->index = n;
                    switch (sym_info.type) {
                    case STT_FUNC:
                        sym->sym_class = SYM_CLASS_FUNCTION;
                        break;
                    case STT_OBJECT:
                        sym->sym_class = SYM_CLASS_REFERENCE;
                        break;
                    default:
                        sym->sym_class = SYM_CLASS_VALUE;
                        break;
                    }
                    *res = sym;
                    cnt++;
                }
            }
            n = tbl->sym_names_next[n];
        }
    }
    return cnt == 1;
}

int find_symbol_by_name(Context * ctx, int frame, ContextAddress ip, const char * name, Symbol ** res) {
    int error = 0;
    int found = 0;
    ELF_File * curr_file = NULL;

    assert(ctx != NULL);
    find_symbol_pos = 0;
    find_symbol_cnt = 0;

#if defined(_WRS_KERNEL)
    {
        char * ptr;
        SYM_TYPE type;

        if (symFindByName(sysSymTbl, name, &ptr, &type) != OK) {
            error = errno;
            assert(error != 0);
            if (error == S_symLib_SYMBOL_NOT_FOUND) error = 0;
        }
        else {
            Symbol * sym = alloc_symbol();
            sym->ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
            sym->frame = STACK_NO_FRAME;
            sym->address = (ContextAddress)ptr;
            sym->has_address = 1;

            if (SYM_IS_TEXT(type)) {
                sym->sym_class = SYM_CLASS_FUNCTION;
            }
            else {
                sym->sym_class = SYM_CLASS_REFERENCE;
            }
            *res = sym;
            found = 1;
        }
    }
#endif

    if (error == 0 && !found && get_sym_context(ctx, frame, ip) < 0) error = errno;

    if (sym_ip != 0) {

        if (error == 0 && !found) {
            /* Search the name in the current compilation unit */
            Trap trap;
            if (set_trap(&trap)) {
                found = find_in_dwarf(name, res);
                clear_trap(&trap);
            }
            else {
                error = trap.error;
            }
        }

        if (error == 0 && !found) {
            /* Search in pub names of the current file */
            ELF_File * file = elf_list_first(sym_ctx, sym_ip, sym_ip);
            if (file == NULL) error = errno;
            while (error == 0 && file != NULL) {
                Trap trap;
                curr_file = file;
                if (set_trap(&trap)) {
                    DWARFCache * cache = get_dwarf_cache(get_dwarf_file(file));
                    found = find_by_name_in_pub_names(cache, name, res);
                    if (!found) found = find_by_name_in_sym_table(cache, name, res);
                    clear_trap(&trap);
                }
                else {
                    error = trap.error;
                    break;
                }
                if (found) break;
                file = elf_list_next(sym_ctx);
                if (file == NULL) error = errno;
            }
            elf_list_done(sym_ctx);
        }

        if (error == 0 && !found) {
            /* Check if the name is one of well known C/C++ names */
            Trap trap;
            if (set_trap(&trap)) {
                unsigned i = 0;
                while (base_types_aliases[i].name) {
                    if (strcmp(name, base_types_aliases[i].name) == 0) {
                        found = find_in_dwarf(base_types_aliases[i].alias, res);
                        if (found) break;
                    }
                    i++;
                }
                if (!found) {
                    i = 0;
                    while (constant_pseudo_symbols[i].name) {
                        if (strcmp(name, constant_pseudo_symbols[i].name) == 0) {
                            Symbol * type = NULL;
                            found = find_in_dwarf(constant_pseudo_symbols[i].type, &type);
                            if (found) {
                                Symbol * sym = alloc_symbol();
                                sym->ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
                                sym->frame = STACK_NO_FRAME;
                                sym->sym_class = SYM_CLASS_VALUE;
                                sym->base = type;
                                sym->length = i;
                                *res = sym;
                                break;
                            }
                        }
                        i++;
                    }
                }
                clear_trap(&trap);
            }
            else {
                error = trap.error;
            }
        }
    }

#if ENABLE_RCBP_TEST
    if (!found) {
        int sym_class = 0;
        void * address = NULL;
        found = find_test_symbol(ctx, name, &address, &sym_class) >= 0;
        if (found) {
            Symbol * sym = alloc_symbol();
            sym->ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
            sym->frame = STACK_NO_FRAME;
            sym->address = (ContextAddress)address;
            sym->has_address = 1;
            sym->sym_class = sym_class;
            *res = sym;
        }
    }
#endif

    if (error == 0 && !found) {
        /* Search in pub names of all other files */
        ELF_File * file = elf_list_first(sym_ctx, 0, ~(ContextAddress)0);
        if (file == NULL) error = errno;
        while (error == 0 && file != NULL) {
            if (file != curr_file) {
                Trap trap;
                if (set_trap(&trap)) {
                    DWARFCache * cache = get_dwarf_cache(get_dwarf_file(file));
                    found = find_by_name_in_pub_names(cache, name, res);
                    if (!found) found = find_by_name_in_sym_table(cache, name, res);
                    clear_trap(&trap);
                }
                else {
                    error = trap.error;
                    break;
                }
                if (found) break;
            }
            file = elf_list_next(sym_ctx);
            if (file == NULL) error = errno;
        }
        elf_list_done(sym_ctx);
        sym_ip = 0;
    }

    if (error == 0 && !found) error = ERR_SYM_NOT_FOUND;

    assert(error || (*res != NULL && (*res)->ctx != NULL));

    if (error) {
        errno = error;
        return -1;
    }
    return 0;
}

int find_symbol_in_scope(Context * ctx, int frame, ContextAddress ip, Symbol * scope, const char * name, Symbol ** res) {
    int error = 0;
    int found = 0;

    *res = NULL;
    find_symbol_pos = 0;
    find_symbol_cnt = 0;
    if (get_sym_context(ctx, frame, ip) < 0) error = errno;

    if (!error && scope == NULL && sym_ip != 0) {
        ELF_File * file = elf_list_first(sym_ctx, sym_ip, sym_ip);
        if (file == NULL) error = errno;
        while (error == 0 && file != NULL) {
            Trap trap;
            if (set_trap(&trap)) {
                DWARFCache * cache = get_dwarf_cache(get_dwarf_file(file));
                UnitAddressRange * range = find_comp_unit_addr_range(cache, sym_ip, sym_ip);
                if (range != NULL) {
                    find_in_object_tree(range->mUnit->mObject, 0, 0, name);
                    if (find_symbol_cnt > 0) {
                        *res = find_symbol_buf[find_symbol_pos++];
                        found = 1;
                    }
                }
                if (!found) {
                    found = find_by_name_in_sym_table(cache, name, res);
                }
                clear_trap(&trap);
            }
            else {
                error = trap.error;
                break;
            }
            if (found) break;
            file = elf_list_next(sym_ctx);
            if (file == NULL) error = errno;
        }
        elf_list_done(sym_ctx);
    }

    if (!found && !error && scope != NULL && scope->obj != NULL) {
        Trap trap;
        if (set_trap(&trap)) {
            find_in_object_tree(scope->obj, 0, 0, name);
            if (find_symbol_cnt > 0) {
                *res = find_symbol_buf[find_symbol_pos++];
                found = 1;
            }
            clear_trap(&trap);
        }
        else {
            error = trap.error;
        }
    }

    if (error == 0 && !found) error = ERR_SYM_NOT_FOUND;

    assert(error || (*res != NULL && (*res)->ctx != NULL));

    if (error) {
        errno = error;
        return -1;
    }
    return 0;
}

static int find_by_addr_in_unit(ObjectInfo * obj, int level, ContextAddress rt_offs, ContextAddress addr, Symbol ** res) {
    while (obj != NULL) {
        switch (obj->mTag) {
        case TAG_compile_unit:
        case TAG_partial_unit:
        case TAG_module:
        case TAG_global_subroutine:
        case TAG_inlined_subroutine:
        case TAG_lexical_block:
        case TAG_with_stmt:
        case TAG_try_block:
        case TAG_catch_block:
        case TAG_subroutine:
        case TAG_subprogram:
            if (check_in_range(obj, rt_offs, addr)) {
                object2symbol(obj, res);
                return 1;
            }
            if (check_in_range(obj, rt_offs, sym_ip)) {
                return find_by_addr_in_unit(get_dwarf_children(obj), level + 1, rt_offs, addr, res);
            }
            break;
        case TAG_formal_parameter:
        case TAG_unspecified_parameters:
        case TAG_local_variable:
            if (sym_frame == STACK_NO_FRAME) break;
        case TAG_variable:
            {
                U8_T lc = 0;
                /* Ignore location evaluation errors. For example, the error can be caused by
                 * the object not being mapped into the context memory */
                if (get_num_prop(obj, AT_location, &lc) && lc <= addr) {
                    U8_T sz = 0;
                    if (!get_num_prop(obj, AT_byte_size, &sz)) {
                        /* If object size unknown, continue search */
                        if (get_error_code(errno) == ERR_SYM_NOT_FOUND) break;
                        exception(errno);
                    }
                    if (lc + sz > addr) {
                        object2symbol(obj, res);
                        return 1;
                    }
                }
            }
            break;
        }
        obj = obj->mSibling;
    }
    return 0;
}

static int find_by_addr_in_sym_tables(ContextAddress addr, Symbol ** res) {
    ELF_File * file = NULL;
    ELF_Section * section = NULL;
    ELF_SymbolInfo sym_info;
    ContextAddress lt_addr = elf_map_to_link_time_address(sym_ctx, addr, &file, &section);
    elf_find_symbol_by_address(section, lt_addr, &sym_info);
    while (sym_info.sym_section != NULL) {
        int sym_class = SYM_CLASS_UNKNOWN;
        assert(sym_info.section == section);
        switch (sym_info.type) {
        case STT_FUNC:
            sym_class = SYM_CLASS_FUNCTION;
            break;
        case STT_OBJECT:
            sym_class = SYM_CLASS_REFERENCE;
            break;
        }
        if (sym_class != SYM_CLASS_UNKNOWN) {
            ContextAddress sym_addr = (ContextAddress)sym_info.value;
            if (file->type == ET_REL) sym_addr += (ContextAddress)section->addr;
            assert(sym_addr <= lt_addr);
            if (sym_addr + sym_info.size > lt_addr) {
                Symbol * sym = alloc_symbol();
                sym->frame = STACK_NO_FRAME;
                sym->ctx = context_get_group(sym_ctx, CONTEXT_GROUP_SYMBOLS);
                sym->tbl = sym_info.sym_section;
                sym->index = sym_info.sym_index;
                sym->sym_class = sym_class;
                *res = sym;
                return 1;
            }
            return 0;
        }
        elf_prev_symbol_by_address(&sym_info);
    }
    return 0;
}

int find_symbol_by_addr(Context * ctx, int frame, ContextAddress addr, Symbol ** res) {
    Trap trap;
    int found = 0;
    ContextAddress rt_addr = 0;
    UnitAddressRange * range = NULL;

    find_symbol_pos = 0;
    find_symbol_cnt = 0;
    if (!set_trap(&trap)) return -1;
    if (frame == STACK_TOP_FRAME && (frame = get_top_frame(ctx)) < 0) exception(errno);
    if (get_sym_context(ctx, frame, addr) < 0) exception(errno);
    range = elf_find_unit(sym_ctx, addr, addr, &rt_addr);
    if (range != NULL) found = find_by_addr_in_unit(
        get_dwarf_children(range->mUnit->mObject),
        0, rt_addr - range->mAddr, addr, res);
    if (!found) found = find_by_addr_in_sym_tables(addr, res);
    if (!found && sym_ip != 0) {
        /* Search in compilation unit that contains stack frame PC */
        range = elf_find_unit(sym_ctx, sym_ip, sym_ip, &rt_addr);
        if (range != NULL) found = find_by_addr_in_unit(
            get_dwarf_children(range->mUnit->mObject),
            0, rt_addr - range->mAddr, addr, res);
    }
    if (!found) exception(ERR_SYM_NOT_FOUND);
    clear_trap(&trap);
    return 0;
}

int find_next_symbol(Symbol ** sym) {
    if (find_symbol_pos < find_symbol_cnt) {
        *sym = find_symbol_buf[find_symbol_pos++];
        return 0;
    }
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

static void enumerate_local_vars(ObjectInfo * obj, int level, ContextAddress rt_offs,
                                 EnumerateSymbolsCallBack * call_back, void * args) {
    while (obj != NULL) {
        switch (obj->mTag) {
        case TAG_compile_unit:
        case TAG_partial_unit:
        case TAG_module:
        case TAG_global_subroutine:
        case TAG_inlined_subroutine:
        case TAG_lexical_block:
        case TAG_with_stmt:
        case TAG_try_block:
        case TAG_catch_block:
        case TAG_subroutine:
        case TAG_subprogram:
            if (check_in_range(obj, rt_offs, sym_ip)) {
                enumerate_local_vars(get_dwarf_children(obj), level + 1, rt_offs, call_back, args);
                if (level == 0) return;
            }
            break;
        case TAG_formal_parameter:
        case TAG_unspecified_parameters:
        case TAG_local_variable:
        case TAG_variable:
            if (level > 0) {
                Context * org_ctx = sym_ctx;
                int org_frame = sym_frame;
                ContextAddress org_ip = sym_ip;
                Symbol * sym = NULL;
                object2symbol(find_definition(obj), &sym);
                call_back(args, sym);
                sym_ctx = org_ctx;
                sym_frame = org_frame;
                sym_ip = org_ip;
            }
            break;
        }
        obj = obj->mSibling;
    }
}

int enumerate_symbols(Context * ctx, int frame, EnumerateSymbolsCallBack * call_back, void * args) {
    Trap trap;
    if (!set_trap(&trap)) return -1;
    if (get_sym_context(ctx, frame, 0) < 0) exception(errno);
    if (sym_ip != 0) {
        ContextAddress rt_addr = 0;
        UnitAddressRange * range = elf_find_unit(sym_ctx, sym_ip, sym_ip, &rt_addr);
        if (range != NULL) enumerate_local_vars(
            get_dwarf_children(range->mUnit->mObject),
            0, rt_addr - range->mAddr, call_back, args);
    }
    clear_trap(&trap);
    return 0;
}

const char * symbol2id(const Symbol * sym) {
    static char id[256];

    assert(sym->magic == SYMBOL_MAGIC);
    if (sym->base) {
        char base[256];
        assert(sym->ctx == sym->base->ctx);
        assert(sym->frame == STACK_NO_FRAME);
        strcpy(base, symbol2id(sym->base));
        snprintf(id, sizeof(id), "@P%X.%"PRIX64".%s", sym->sym_class, (uint64_t)sym->length, base);
    }
    else {
        ELF_File * file = NULL;
        uint64_t obj_index = 0;
        uint64_t var_index = 0;
        unsigned tbl_index = 0;
        int frame = sym->frame;
        if (sym->obj != NULL) file = sym->obj->mCompUnit->mFile;
        if (sym->tbl != NULL) file = sym->tbl->file;
        if (sym->obj != NULL) obj_index = sym->obj->mID;
        if (sym->var != NULL) var_index = sym->var->mID;
        if (sym->tbl != NULL) tbl_index = sym->tbl->index;
        if (frame == STACK_TOP_FRAME) frame = get_top_frame(sym->ctx);
        assert(sym->var == NULL || sym->var->mCompUnit->mFile == file);
        snprintf(id, sizeof(id), "@S%X.%lX.%lX.%"PRIX64".%"PRIX64".%"PRIX64".%X.%d.%X.%X.%X.%s",
            sym->sym_class,
            file ? (unsigned long)file->dev : 0ul,
            file ? (unsigned long)file->ino : 0ul,
            file ? file->mtime : (int64_t)0,
            obj_index, var_index, tbl_index,
            frame, sym->index,
            sym->dimension, sym->cardinal,
            sym->ctx->id);
    }
    return id;
}

static uint64_t read_hex(const char ** s) {
    uint64_t res = 0;
    const char * p = *s;
    for (;;) {
        if (*p >= '0' && *p <= '9') res = (res << 4) | (*p - '0');
        else if (*p >= 'A' && *p <= 'F') res = (res << 4) | (*p - 'A' + 10);
        else break;
        p++;
    }
    *s = p;
    return res;
}

static int read_int(const char ** s) {
    int neg = 0;
    int res = 0;
    const char * p = *s;
    if (*p == '-') {
        neg = 1;
        p++;
    }
    for (;;) {
        if (*p >= '0' && *p <= '9') res = res * 10 + (*p - '0');
        else break;
        p++;
    }
    *s = p;
    return neg ? -res : res;
}

int id2symbol(const char * id, Symbol ** res) {
    Symbol * sym = alloc_symbol();
    dev_t dev = 0;
    ino_t ino = 0;
    int64_t mtime;
    ContextAddress obj_index = 0;
    ContextAddress var_index = 0;
    unsigned tbl_index = 0;
    ELF_File * file = NULL;
    const char * p;
    Trap trap;

    *res = sym;
    if (id != NULL && id[0] == '@' && id[1] == 'P') {
        p = id + 2;
        sym->sym_class = (int)read_hex(&p);
        if (*p == '.') p++;
        sym->length = (ContextAddress)read_hex(&p);
        if (*p == '.') p++;
        if (id2symbol(p, &sym->base)) return -1;
        sym->ctx = sym->base->ctx;
        sym->frame = STACK_NO_FRAME;
        return 0;
    }
    else if (id != NULL && id[0] == '@' && id[1] == 'S') {
        p = id + 2;
        sym->sym_class = (int)read_hex(&p);
        if (*p == '.') p++;
        dev = (dev_t)read_hex(&p);
        if (*p == '.') p++;
        ino = (ino_t)read_hex(&p);
        if (*p == '.') p++;
        mtime = (int64_t)read_hex(&p);
        if (*p == '.') p++;
        obj_index = (ContextAddress)read_hex(&p);
        if (*p == '.') p++;
        var_index = (ContextAddress)read_hex(&p);
        if (*p == '.') p++;
        tbl_index = (unsigned)read_hex(&p);
        if (*p == '.') p++;
        sym->frame = read_int(&p);
        if (*p == '.') p++;
        sym->index = (unsigned)read_hex(&p);
        if (*p == '.') p++;
        sym->dimension = (unsigned)read_hex(&p);
        if (*p == '.') p++;
        sym->cardinal = (unsigned)read_hex(&p);
        if (*p == '.') p++;
        sym->ctx = id2ctx(p);
        if (sym->ctx == NULL) {
            errno = ERR_INV_CONTEXT;
            return -1;
        }
        if (dev == 0 && ino == 0 && mtime == 0) return 0;
        file = elf_open_inode(sym->ctx, dev, ino, mtime);
        if (file == NULL) return -1;
        if (set_trap(&trap)) {
            DWARFCache * cache = get_dwarf_cache(file);
            if (obj_index) {
                sym->obj = find_object(cache, obj_index);
                if (sym->obj == NULL) exception(ERR_INV_CONTEXT);
            }
            if (var_index) {
                sym->var = find_object(cache, var_index);
                if (sym->var == NULL) exception(ERR_INV_CONTEXT);
            }
            if (tbl_index) {
                if (tbl_index >= file->section_cnt) exception(ERR_INV_CONTEXT);
                sym->tbl = file->sections + tbl_index;
            }
            clear_trap(&trap);
            return 0;
        }
    }
    else {
        errno = ERR_INV_CONTEXT;
    }
    return -1;
}

ContextAddress is_plt_section(Context * ctx, ContextAddress addr) {
    ELF_File * file = NULL;
    ELF_Section * sec = NULL;
    ContextAddress res = elf_map_to_link_time_address(ctx, addr, &file, &sec);
    if (res == 0 || sec == NULL) return 0;
    if (sec->name == NULL) return 0;
    if (strcmp(sec->name, ".plt") != 0) return 0;
    return (ContextAddress)sec->addr + (addr - res);
}

int get_stack_tracing_info(Context * ctx, ContextAddress rt_addr, StackTracingInfo ** info) {
    /* TODO: no debug info exists for linux-gate.so, need to read stack tracing information from the kernel  */
    ELF_File * file = NULL;
    ELF_Section * sec = NULL;
    ContextAddress lt_addr = 0;
    int error = 0;
    Trap trap;

    *info = NULL;

    lt_addr = elf_map_to_link_time_address(ctx, rt_addr, &file, &sec);
    if (file != NULL) {
        /* This assert fails because of ambiguity in Linux memory maps:
         * assert(rt_addr == elf_map_to_run_time_address(ctx, file, sec, lt_addr)); */
        if (set_trap(&trap)) {
            get_dwarf_stack_frame_info(ctx, file, sec, lt_addr);
            if (dwarf_stack_trace_fp->cmds_cnt > 0) {
                static StackTracingInfo buf;
                buf.addr = (ContextAddress)dwarf_stack_trace_addr - lt_addr + rt_addr;
                buf.size = (ContextAddress)dwarf_stack_trace_size;
                buf.fp = dwarf_stack_trace_fp;
                buf.regs = dwarf_stack_trace_regs;
                buf.reg_cnt = dwarf_stack_trace_regs_cnt;
                *info = &buf;
            }
            clear_trap(&trap);
        }
        else {
            error = trap.error;
        }
    }

    if (error) {
        errno = error;
        return -1;
    }
    return 0;
}

int get_next_stack_frame(StackFrame * frame, StackFrame * down) {
    int error = 0;
    uint64_t ip = 0;
    Context * ctx = frame->ctx;
    StackTracingInfo * info = NULL;

    if (read_reg_value(frame, get_PC_definition(ctx), &ip) < 0) {
        if (frame->is_top_frame) error = errno;
    }
    else if (get_stack_tracing_info(ctx, (ContextAddress)ip, &info) < 0) {
        error = errno;
    }
    else if (info != NULL) {
        Trap trap;
        if (set_trap(&trap)) {
            int i;
            LocationExpressionState * state;
            state = evaluate_location_expression(ctx, frame, info->fp->cmds, info->fp->cmds_cnt, NULL, 0);
            if (state->stk_pos != 1) str_exception(ERR_OTHER, "Invalid stack trace expression");
            frame->fp = (ContextAddress)state->stk[0];
            frame->is_walked = 1;
            for (i = 0; i < info->reg_cnt; i++) {
                int ok = 0;
                uint64_t v = 0;
                Trap trap_reg;
                if (set_trap(&trap_reg)) {
                    /* If a saved register value cannot be evaluated - ignore it */
                    state = evaluate_location_expression(ctx, frame, info->regs[i]->cmds, info->regs[i]->cmds_cnt, NULL, 0);
                    if (state->stk_pos == 1) {
                        v = state->stk[0];
                        ok = 1;
                    }
                    clear_trap(&trap_reg);
                }
                if (ok && write_reg_value(down, info->regs[i]->reg, v) < 0) exception(errno);
            }
            clear_trap(&trap);
        }
        else {
            frame->fp = 0;
        }
    }
    if (error) {
        errno = error;
        return -1;
    }
    return 0;
}

const char * get_symbol_file_name(MemoryRegion * module) {
    int error = 0;
    ELF_File * file = module ? elf_open_memory_region_file(module, &error) : NULL;
    errno = error;
    if (file == NULL && module == NULL) return NULL;
    if (file == NULL) return module->file_name;
    if (file->debug_info_file_name) return file->debug_info_file_name;
    return file->name;
}

void ini_symbols_lib(void) {
}

/*************** Functions for retrieving symbol properties ***************************************/

static int unpack(const Symbol * sym) {
    assert(sym->base == NULL);
    assert(!is_array_type_pseudo_symbol(sym));
    assert(!is_cardinal_type_pseudo_symbol(sym));
    assert(!is_constant_pseudo_symbol(sym));
    assert(sym->obj == NULL || sym->obj->mTag != 0);
    assert(sym->obj == NULL || sym->obj->mCompUnit->mFile->dwarf_dt_cache != NULL);
    return get_sym_context(sym->ctx, sym->frame, 0);
}

static U8_T get_default_lower_bound(ObjectInfo * obj) {
    switch (obj->mCompUnit->mLanguage) {
    case LANG_FORTRAN77:
    case LANG_FORTRAN90:
    case LANG_FORTRAN95:
        return 1;
    }
    return 0;
}

static U8_T get_array_index_length(ObjectInfo * obj) {
    U8_T x, y;

    if (get_num_prop(obj, AT_count, &x)) return x;
    if (get_num_prop(obj, AT_upper_bound, &x)) {
        if (!get_num_prop(obj, AT_lower_bound, &y)) {
            y = get_default_lower_bound(obj);
        }
        return x + 1 - y;
    }
    if (obj->mTag == TAG_enumeration_type) {
        ObjectInfo * c = get_dwarf_children(obj);
        x = 0;
        while (c != NULL) {
            x++;
            c = c->mSibling;
        }
        return x;
    }
    return 0;
}

static void alloc_cardinal_type_pseudo_symbol(Context * ctx, unsigned size, Symbol ** type) {
    *type = alloc_symbol();
    (*type)->ctx = context_get_group(ctx, CONTEXT_GROUP_SYMBOLS);
    (*type)->frame = STACK_NO_FRAME;
    (*type)->sym_class = SYM_CLASS_TYPE;
    (*type)->cardinal = size;
}

static int map_to_sym_table(ObjectInfo * obj, Symbol ** sym) {
    int found = 0;
    if (obj->mFlags & DOIF_external) {
        Trap trap;
        DWARFCache * cache = get_dwarf_cache(obj->mCompUnit->mFile);
        if (set_trap(&trap)) {
            PropertyValue p;
            read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_MIPS_linkage_name, &p);
            if (p.mAddr != NULL) found = find_by_name_in_sym_table(cache, (char *)p.mAddr, sym);
            clear_trap(&trap);
        }
        else if (get_error_code(trap.error) == ERR_SYM_NOT_FOUND && set_trap(&trap)) {
            PropertyValue p;
            read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_mangled, &p);
            if (p.mAddr != NULL) found = find_by_name_in_sym_table(cache, (char *)p.mAddr, sym);
            clear_trap(&trap);
        }
        else if (get_error_code(trap.error) == ERR_SYM_NOT_FOUND && obj->mName != NULL) {
            found = find_by_name_in_sym_table(cache, obj->mName, sym);
        }
    }
    return found;
}

static U8_T read_string_length(ObjectInfo * obj);

static int get_object_size(ObjectInfo * obj, unsigned dimension, U8_T * byte_size, U8_T * bit_size) {
    U8_T n = 0, m = 0;
    obj = find_definition(obj);
    if (get_num_prop(obj, AT_byte_size, &n)) {
        *byte_size = n;
        return 1;
    }
    if (get_num_prop(obj, AT_bit_size, &n)) {
        *byte_size = (n + 7) / 8;
        *bit_size = n;
        return 1;
    }
    switch (obj->mTag) {
    case TAG_enumerator:
    case TAG_formal_parameter:
    case TAG_unspecified_parameters:
    case TAG_template_type_param:
    case TAG_global_variable:
    case TAG_local_variable:
    case TAG_variable:
    case TAG_inheritance:
    case TAG_member:
    case TAG_constant:
    case TAG_const_type:
    case TAG_volatile_type:
    case TAG_restrict_type:
    case TAG_shared_type:
    case TAG_typedef:
        if (obj->mType == NULL) return 0;
        return get_object_size(obj->mType, 0, byte_size, bit_size);
    case TAG_compile_unit:
    case TAG_partial_unit:
    case TAG_module:
    case TAG_global_subroutine:
    case TAG_inlined_subroutine:
    case TAG_lexical_block:
    case TAG_with_stmt:
    case TAG_try_block:
    case TAG_catch_block:
    case TAG_subroutine:
    case TAG_subprogram:
        if ((obj->mFlags & DOIF_ranges) == 0 && obj->u.mCode.mHighPC.mAddr > obj->u.mCode.mLowPC) {
            *byte_size = obj->u.mCode.mHighPC.mAddr - obj->u.mCode.mLowPC;
            return 1;
        }
        return 0;
    case TAG_string_type:
        *byte_size = read_string_length(obj);
        return 1;
    case TAG_array_type:
        {
            unsigned i = 0;
            U8_T length = 1;
            ObjectInfo * idx = get_dwarf_children(obj);
            while (idx != NULL) {
                if (i++ >= dimension) length *= get_array_index_length(idx);
                idx = idx->mSibling;
            }
            if (get_num_prop(obj, AT_stride_size, &n)) {
                *byte_size = (n * length + 7) / 8;
                *bit_size = n * length;
                return 1;
            }
            if (obj->mType == NULL) return 0;
            if (!get_object_size(obj->mType, 0, &n, &m)) return 0;
            if (m != 0) {
                *byte_size = (m * length + 7) / 8;
                *bit_size = m * length;
            }
            *byte_size = n * length;
        }
        return 1;
    }
    return 0;
}

static void read_object_value(PropertyValue * v, void ** value, size_t * size, int * big_endian) {
    if (v->mPieces != NULL) {
        StackFrame * frame = NULL;
        if (get_frame_info(v->mContext, v->mFrame, &frame) < 0) exception(errno);
        read_location_peices(v->mContext, frame, v->mPieces, v->mPieceCnt, v->mBigEndian, value, size);
        *big_endian = v->mBigEndian;
    }
    else if (v->mAddr != NULL) {
        *value = v->mAddr;
        *size = v->mSize;
        *big_endian = v->mBigEndian;
    }
    else {
        U1_T * bf = NULL;
        U8_T val_size = 0;
        U8_T bit_size = 0;

        if (get_object_size(v->mObject, 0, &val_size, &bit_size)) {}
        else if (v->mAttr == AT_string_length) val_size = v->mObject->mCompUnit->mDesc.mAddressSize;
        else str_exception(ERR_INV_DWARF, "Unknown object size");
        bf = (U1_T *)tmp_alloc((size_t)val_size);
        if (v->mForm == FORM_EXPR_VALUE) {
            if (context_read_mem(sym_ctx, (ContextAddress)v->mValue, bf, (size_t)val_size) < 0) exception(errno);
            *big_endian = v->mBigEndian;
        }
        else {
            U1_T * p = (U1_T *)&v->mValue;
            if (val_size > sizeof(v->mValue)) str_exception(ERR_INV_DWARF, "Unknown object size");
            if (big_endian_host()) p += (size_t)val_size;
            memcpy(bf, p, (size_t)val_size);
            *big_endian = big_endian_host();
        }
        if (bit_size % 8 != 0) bf[bit_size / 8] &= (1 << (bit_size % 8)) - 1;
        *size = (size_t)val_size;
        *value = bf;
    }
}

static U8_T read_cardinal_object_value(PropertyValue * v) {
    void * value = NULL;
    size_t size = 0;
    size_t i = 0;
    int big_endian = 0;
    U8_T n = 0;

    read_object_value(v, &value, &size, &big_endian);
    if (size > 8) str_exception(ERR_INV_DWARF, "Invalid object size");
    for (i = 0; i < size; i++) {
        n = (n << 8) | ((U1_T *)value)[big_endian ? i : size - i - 1];
    }
    return n;
}

static U8_T read_string_length(ObjectInfo * obj) {
    Trap trap;
    U8_T len = 0;

    if (set_trap(&trap)) {
        PropertyValue v;
        read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_string_length, &v);
        len = read_cardinal_object_value(&v);
        clear_trap(&trap);
        return len;
    }
    else if (trap.error != ERR_SYM_NOT_FOUND) {
        exception(trap.error);
    }
    if (get_num_prop(obj, AT_byte_size, &len)) return len;
    str_exception(ERR_INV_DWARF, "Unknown length of a string type");
    return 0;
}

int get_symbol_class(const Symbol * sym, int * sym_class) {
    assert(sym->magic == SYMBOL_MAGIC);
    *sym_class = sym->sym_class;
    return 0;
}

int get_symbol_type(const Symbol * sym, Symbol ** type) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (sym->sym_class == SYM_CLASS_TYPE && obj == NULL) {
        *type = (Symbol *)sym;
        return 0;
    }
    if (is_constant_pseudo_symbol(sym)) {
        *type = sym->base;
        return 0;
    }
    if (sym->sym_class == SYM_CLASS_FUNCTION) {
        *type = alloc_symbol();
        (*type)->ctx = sym->ctx;
        (*type)->frame = STACK_NO_FRAME;
        (*type)->sym_class = SYM_CLASS_TYPE;
        (*type)->base = (Symbol *)sym;
        return 0;
    }
    if (unpack(sym) < 0) return -1;
    if (is_modified_type(obj)) {
        obj = obj->mType;
    }
    else {
        obj = get_object_type(obj);
    }
    if (obj == NULL) {
        *type = NULL;
    }
    else if (obj == sym->obj) {
        *type = (Symbol *)sym;
    }
    else {
        object2symbol(find_definition(obj), type);
    }
    return 0;
}

int get_symbol_type_class(const Symbol * sym, int * type_class) {
    U8_T x;
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_constant_pseudo_symbol(sym)) return get_symbol_type_class(sym->base, type_class);
    if (is_array_type_pseudo_symbol(sym)) {
        if (sym->base->sym_class == SYM_CLASS_FUNCTION) *type_class = TYPE_CLASS_FUNCTION;
        else if (sym->length > 0) *type_class = TYPE_CLASS_ARRAY;
        else *type_class = TYPE_CLASS_POINTER;
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym)) {
        *type_class = TYPE_CLASS_CARDINAL;
        return 0;
    }
    if (unpack(sym) < 0) return -1;
    while (obj != NULL) {
        switch (obj->mTag) {
        case TAG_global_subroutine:
        case TAG_inlined_subroutine:
        case TAG_subroutine:
        case TAG_subprogram:
        case TAG_entry_point:
        case TAG_subroutine_type:
            *type_class = TYPE_CLASS_FUNCTION;
            return 0;
        case TAG_array_type:
        case TAG_string_type:
            *type_class = TYPE_CLASS_ARRAY;
            return 0;
        case TAG_enumeration_type:
        case TAG_enumerator:
            *type_class = TYPE_CLASS_ENUMERATION;
            return 0;
        case TAG_pointer_type:
        case TAG_reference_type:
        case TAG_mod_pointer:
        case TAG_mod_reference:
            *type_class = TYPE_CLASS_POINTER;
            return 0;
        case TAG_ptr_to_member_type:
            *type_class = TYPE_CLASS_MEMBER_PTR;
            return 0;
        case TAG_class_type:
        case TAG_structure_type:
        case TAG_union_type:
        case TAG_interface_type:
            *type_class = TYPE_CLASS_COMPOSITE;
            return 0;
        case TAG_base_type:
            if (get_num_prop(obj, AT_encoding, &x)) {
                switch ((int)x) {
                case ATE_address:
                    *type_class = TYPE_CLASS_POINTER;
                    return 0;
                case ATE_boolean:
                    *type_class = TYPE_CLASS_INTEGER;
                    return 0;
                case ATE_float:
                    *type_class = TYPE_CLASS_REAL;
                    return 0;
                case ATE_signed:
                case ATE_signed_char:
                    *type_class = TYPE_CLASS_INTEGER;
                    return 0;
                case ATE_unsigned:
                case ATE_unsigned_char:
                    *type_class = TYPE_CLASS_CARDINAL;
                    return 0;
                }
            }
            *type_class = TYPE_CLASS_UNKNOWN;
            return 0;
        case TAG_fund_type:
            switch (obj->u.mFundType) {
            case FT_boolean:
                *type_class = TYPE_CLASS_INTEGER;
                return 0;
            case FT_char:
                *type_class = TYPE_CLASS_INTEGER;
                return 0;
            case FT_dbl_prec_float:
            case FT_ext_prec_float:
            case FT_float:
                *type_class = TYPE_CLASS_REAL;
                return 0;
            case FT_signed_char:
            case FT_signed_integer:
            case FT_signed_long:
            case FT_signed_short:
            case FT_short:
            case FT_integer:
            case FT_long:
                *type_class = TYPE_CLASS_INTEGER;
                return 0;
            case FT_unsigned_char:
            case FT_unsigned_integer:
            case FT_unsigned_long:
            case FT_unsigned_short:
                *type_class = TYPE_CLASS_CARDINAL;
                return 0;
            case FT_pointer:
                *type_class = TYPE_CLASS_POINTER;
                return 0;
            case FT_void:
                *type_class = TYPE_CLASS_CARDINAL;
                return 0;
            case FT_label:
            case FT_complex:
            case FT_dbl_prec_complex:
            case FT_ext_prec_complex:
                break;
            }
            *type_class = TYPE_CLASS_UNKNOWN;
            return 0;
        case TAG_subrange_type:
        case TAG_packed_type:
        case TAG_volatile_type:
        case TAG_restrict_type:
        case TAG_shared_type:
        case TAG_const_type:
        case TAG_typedef:
        case TAG_formal_parameter:
        case TAG_unspecified_parameters:
        case TAG_global_variable:
        case TAG_local_variable:
        case TAG_variable:
        case TAG_inheritance:
        case TAG_member:
        case TAG_constant:
        case TAG_template_type_param:
            obj = obj->mType;
            break;
        default:
            obj = NULL;
            break;
        }
    }
    if (sym->tbl != NULL) {
        ELF_SymbolInfo info;
        unpack_elf_symbol_info(sym->tbl, sym->index, &info);
        if (info.type == STT_FUNC) {
            *type_class = TYPE_CLASS_FUNCTION;
            return 0;
        }
    }
    *type_class = TYPE_CLASS_UNKNOWN;
    return 0;
}

int get_symbol_update_policy(const Symbol * sym, char ** id, int * policy) {
    assert(sym->magic == SYMBOL_MAGIC);
    *id = sym->ctx->id;
    *policy = context_has_state(sym->ctx) ? UPDATE_ON_EXE_STATE_CHANGES : UPDATE_ON_MEMORY_MAP_CHANGES;
    return 0;
}

int get_symbol_name(const Symbol * sym, char ** name) {
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym) || is_cardinal_type_pseudo_symbol(sym)) {
        *name = NULL;
    }
    else if (is_constant_pseudo_symbol(sym)) {
        *name = (char *)constant_pseudo_symbols[(int)sym->length].name;
    }
    else if (sym->obj != NULL) {
        *name = (char *)sym->obj->mName;
    }
    else if (sym->tbl != NULL) {
        size_t i;
        ELF_SymbolInfo info;
        unpack_elf_symbol_info(sym->tbl, sym->index, &info);
        for (i = 0;; i++) {
            if (info.name[i] == 0) {
                *name = info.name;
                break;
            }
            if (info.name[i] == '@' && info.name[i + 1] == '@') {
                *name = (char *)tmp_alloc_zero(i + 1);
                memcpy(*name, info.name, i);
                break;
            }
        }
    }
    else {
        *name = NULL;
    }
    return 0;
}

int get_symbol_size(const Symbol * sym, ContextAddress * size) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_constant_pseudo_symbol(sym)) return get_symbol_size(sym->base, size);
    if (is_array_type_pseudo_symbol(sym)) {
        if (sym->length > 0) {
            if (get_symbol_size(sym->base, size)) return -1;
            *size *= sym->length;
        }
        else {
            Symbol * base = sym->base;
            while (base->obj == NULL && base->base != NULL) base = base->base;
            if (base->obj != NULL) *size = base->obj->mCompUnit->mDesc.mAddressSize;
            else *size = context_word_size(sym->ctx);
        }
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym)) {
        *size = sym->cardinal;
        return 0;
    }
    if (sym->has_size != 0) {
        *size = sym->size;
        return 0;
    }
    if (unpack(sym) < 0) return -1;
    *size = 0;
    if (obj != NULL) {
        int ok = 0;
        U8_T sz = 0;
        U8_T n = 0;

        ok = get_object_size(obj, sym->dimension, &sz, &n);
        if (!ok && sym->sym_class == SYM_CLASS_REFERENCE) {
            Trap trap;
            if (set_trap(&trap)) {
                PropertyValue v;
                read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_location, &v);
                if (v.mPieces) {
                    U4_T i = 0, j = 0;
                    while (i < v.mPieceCnt) {
                        LocationPiece * p = v.mPieces + i++;
                        if (p->bit_size) j += p->bit_size;
                        else sz += p->size;
                    }
                    sz += (j + 7) / 8;
                    ok = 1;
                }
                clear_trap(&trap);
            }
        }
        if (!ok && sym->sym_class == SYM_CLASS_REFERENCE) {
            Symbol * elf_sym = NULL;
            ContextAddress elf_sym_size = 0;
            if (map_to_sym_table(obj, &elf_sym) && get_symbol_size(elf_sym, &elf_sym_size) == 0) {
                sz = elf_sym_size;
                ok = 1;
            }
        }
        if (!ok) {
            set_errno(ERR_INV_DWARF, "Object has no size attribute");
            return -1;
        }
        *size = (ContextAddress)sz;
    }
    else if (sym->tbl != NULL) {
        ELF_SymbolInfo info;
        unpack_elf_symbol_info(sym->tbl, sym->index, &info);
        switch (info.type) {
        case STT_OBJECT:
        case STT_FUNC:
            *size = (ContextAddress)info.size;
            break;
        default:
            *size = info.sym_section->file->elf64 ? 8 : 4;
            break;
        }
    }
    else {
        set_errno(ERR_OTHER, "Debug info not available");
        return -1;
    }
    return 0;
}

int get_symbol_base_type(const Symbol * sym, Symbol ** base_type) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym)) {
        if (sym->base->sym_class == SYM_CLASS_FUNCTION) {
            if (sym->base->obj != NULL && sym->base->obj->mType != NULL) {
                if (unpack(sym->base) < 0) return -1;
                object2symbol(sym->base->obj->mType, base_type);
                return 0;
            }
            errno = ERR_UNSUPPORTED;
            return -1;
        }
        *base_type = sym->base;
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym) || is_constant_pseudo_symbol(sym)) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    if (sym->sym_class == SYM_CLASS_FUNCTION) {
        if (sym->obj != NULL && sym->obj->mType != NULL) {
            object2symbol(sym->obj->mType, base_type);
            return 0;
        }
        errno = ERR_UNSUPPORTED;
        return -1;
    }
    obj = get_original_type(obj);
    if (obj != NULL) {
        if (obj->mTag == TAG_array_type) {
            int i = sym->dimension;
            ObjectInfo * idx = get_dwarf_children(obj);
            while (i > 0 && idx != NULL) {
                idx = idx->mSibling;
                i--;
            }
            if (idx != NULL && idx->mSibling != NULL) {
                object2symbol(obj, base_type);
                (*base_type)->dimension = sym->dimension + 1;
                return 0;
            }
        }
        obj = obj->mType;
        if (obj != NULL) {
            object2symbol(obj, base_type);
            return 0;
        }
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int get_symbol_index_type(const Symbol * sym, Symbol ** index_type) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym)) {
        if (sym->base->sym_class == SYM_CLASS_FUNCTION) {
            errno = ERR_INV_CONTEXT;
            return -1;
        }
        alloc_cardinal_type_pseudo_symbol(sym->ctx, context_word_size(sym->ctx), index_type);
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym) ||
            is_constant_pseudo_symbol(sym) ||
            sym->sym_class == SYM_CLASS_FUNCTION) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    obj = get_original_type(obj);
    if (obj != NULL && obj->mTag == TAG_array_type) {
        int i = sym->dimension;
        ObjectInfo * idx = get_dwarf_children(obj);
        while (i > 0 && idx != NULL) {
            idx = idx->mSibling;
            i--;
        }
        if (idx != NULL) {
            object2symbol(idx, index_type);
            return 0;
        }
    }
    if (obj != NULL && obj->mTag == TAG_string_type) {
        alloc_cardinal_type_pseudo_symbol(sym->ctx, obj->mCompUnit->mDesc.mAddressSize, index_type);
        return 0;
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int get_symbol_container(const Symbol * sym, Symbol ** container) {
    ObjectInfo * obj = sym->obj;
    if (obj != NULL) {
        ObjectInfo * parent = NULL;
        if (unpack(sym) < 0) return -1;
        if (sym->sym_class == SYM_CLASS_TYPE) {
            ObjectInfo * org = get_original_type(obj);
            if (org->mTag == TAG_ptr_to_member_type) {
                U8_T id = 0;
                if (get_num_prop(org, AT_containing_type, &id)) {
                    ObjectInfo * type = find_object(get_dwarf_cache(org->mCompUnit->mFile), (ContextAddress)id);
                    if (type != NULL) {
                        object2symbol(type, container);
                        return 0;
                    }
                }
                set_errno(ERR_INV_DWARF, "Invalid AT_containing_type attribute");
                return -1;
            }
        }
        parent = get_dwarf_parent(obj);
        if (parent != NULL) {
            object2symbol(parent, container);
            return 0;
        }
    }
    errno = ERR_SYM_NOT_FOUND;
    return -1;
}

int get_symbol_length(const Symbol * sym, ContextAddress * length) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym)) {
        if (sym->base->sym_class == SYM_CLASS_FUNCTION) {
            errno = ERR_INV_CONTEXT;
            return -1;
        }
        *length = sym->length == 0 ? 1 : sym->length;
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym) ||
            is_constant_pseudo_symbol(sym) ||
            sym->sym_class == SYM_CLASS_FUNCTION) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    obj = get_original_type(obj);
    if (obj != NULL) {
        if (obj->mTag == TAG_array_type) {
            int i = sym->dimension;
            ObjectInfo * idx = get_dwarf_children(obj);
            while (i > 0 && idx != NULL) {
                idx = idx->mSibling;
                i--;
            }
            if (idx != NULL) {
                Trap trap;
                if (!set_trap(&trap)) return -1;
                *length = (ContextAddress)get_array_index_length(idx);
                clear_trap(&trap);
                return 0;
            }
        }
        if (obj->mTag == TAG_string_type) {
            Trap trap;
            if (!set_trap(&trap)) return -1;
            *length = (ContextAddress)read_string_length(obj);
            clear_trap(&trap);
            return 0;
        }
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int get_symbol_lower_bound(const Symbol * sym, int64_t * value) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym)) {
        if (sym->base->sym_class == SYM_CLASS_FUNCTION) {
            errno = ERR_INV_CONTEXT;
            return -1;
        }
        *value = 0;
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym) ||
            is_constant_pseudo_symbol(sym) ||
            sym->sym_class == SYM_CLASS_FUNCTION) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    obj = get_original_type(obj);
    if (obj != NULL) {
        if (obj->mTag == TAG_array_type) {
            int i = sym->dimension;
            ObjectInfo * idx = get_dwarf_children(obj);
            while (i > 0 && idx != NULL) {
                idx = idx->mSibling;
                i--;
            }
            if (idx != NULL) {
                if (get_num_prop(obj, AT_lower_bound, (U8_T *)value)) return 0;
                if (get_error_code(errno) != ERR_SYM_NOT_FOUND) return -1;
                *value = get_default_lower_bound(obj);
                return 0;
            }
        }
        if (obj->mTag == TAG_string_type) {
            *value = 0;
            return 0;
        }
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int get_symbol_children(const Symbol * sym, Symbol *** children, int * count) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym)) {
        obj = sym->base->obj;
        if (sym->base->sym_class == SYM_CLASS_FUNCTION) {
            if (obj == NULL) {
                *children = NULL;
                *count = 0;
                errno = ERR_SYM_NOT_FOUND;
                return -1;
            }
            else {
                int n = 0;
                int buf_len = 0;
                Symbol ** buf = NULL;
                ObjectInfo * i = get_dwarf_children(obj);
                if (unpack(sym->base) < 0) return -1;
                while (i != NULL) {
                    if (i->mTag == TAG_formal_parameter || i->mTag == TAG_unspecified_parameters) {
                        Symbol * x = NULL;
                        Symbol * y = NULL;
                        object2symbol(i, &x);
                        if (get_symbol_type(x, &y) < 0) return -1;
                        if (buf_len <= n) {
                            buf_len += 16;
                            buf = (Symbol **)tmp_realloc(buf, sizeof(Symbol *) * buf_len);
                        }
                        buf[n++] = y;
                    }
                    i = i->mSibling;
                }
                *children = buf;
                *count = n;
                return 0;
            }
        }
        *children = NULL;
        *count = 0;
        return 0;
    }
    if (is_cardinal_type_pseudo_symbol(sym) || is_constant_pseudo_symbol(sym)) {
        *children = NULL;
        *count = 0;
        return 0;
    }
    if (unpack(sym) < 0) return -1;
    obj = get_original_type(obj);
    if (obj != NULL) {
        int n = 0;
        int buf_len = 0;
        Symbol ** buf = NULL;
        ObjectInfo * i = get_dwarf_children(obj);
        while (i != NULL) {
            Symbol * x = NULL;
            object2symbol(find_definition(i), &x);
            if (buf_len <= n) {
                buf_len += 16;
                buf = (Symbol **)tmp_realloc(buf, sizeof(Symbol *) * buf_len);
            }
            buf[n++] = x;
            i = i->mSibling;
        }
        *children = buf;
        *count = n;
        return 0;
    }
    *children = NULL;
    *count = 0;
    return 0;
}

int get_symbol_offset(const Symbol * sym, ContextAddress * offset) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_array_type_pseudo_symbol(sym) ||
        is_cardinal_type_pseudo_symbol(sym) ||
        is_constant_pseudo_symbol(sym)) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    if (obj != NULL && (obj->mTag == TAG_member || obj->mTag == TAG_inheritance)) {
        U8_T v;
        dwarf_expression_obj_addr = 0;
        if (get_num_prop(obj, AT_data_member_location, &v)) {
            *offset = (ContextAddress)v;
            return 0;
        }
        if (get_num_prop(obj, AT_bit_offset, &v)) {
            set_errno(ERR_OTHER, "Cannot get member offset: the symbol is a bit field");
            return -1;
        }
        if (obj->mFlags & DOIF_declaration) {
            set_errno(ERR_OTHER, "Cannot get member offset: the symbol is a declaration");
            return -1;
        }
    }
    set_errno(ERR_OTHER, "Symbol does not have a member offset");
    return -1;
}

int get_symbol_value(const Symbol * sym, void ** value, size_t * size, int * big_endian) {
    ObjectInfo * obj = sym->obj;
    assert(sym->magic == SYMBOL_MAGIC);
    if (is_constant_pseudo_symbol(sym)) {
        ContextAddress sym_size = 0;
        if (get_symbol_size(sym, &sym_size) < 0) return -1;
        *size = (size_t)sym_size;
        *big_endian = big_endian_host();
        *value = &constant_pseudo_symbols[(int)sym->length].value;
        if (*big_endian && *size < sizeof(ConstantValueType)) {
            *value = (char *)(*value) + (sizeof(ConstantValueType) - *size);
        }
        return 0;
    }
    if (is_array_type_pseudo_symbol(sym) || is_cardinal_type_pseudo_symbol(sym) || sym->var) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    if (obj != NULL) {
        Trap trap;
        PropertyValue v;
        Symbol * s = NULL;
        if (set_trap(&trap)) {
            read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_const_value, &v);
            read_object_value(&v, value, size, big_endian);
            clear_trap(&trap);
            return 0;
        }
        else if (trap.error != ERR_SYM_NOT_FOUND) {
            return -1;
        }
        if (set_trap(&trap)) {
            read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_location, &v);
            read_object_value(&v, value, size, big_endian);
            clear_trap(&trap);
            return 0;
        }
        else if (trap.error != ERR_SYM_NOT_FOUND) {
            return -1;
        }
#if SERVICE_StackTrace || ENABLE_ContextProxy
        if (obj->mTag == TAG_formal_parameter) {
            /* Search call site info */
            if (set_trap(&trap)) {
                RegisterDefinition * reg_def = get_PC_definition(sym_ctx);
                if (reg_def != NULL) {
                    uint64_t addr = 0;
                    ContextAddress rt_addr = 0;
                    UnitAddressRange * range = NULL;
                    Symbol * caller = NULL;
                    StackFrame * info = NULL;
                    if (get_frame_info(sym_ctx, get_prev_frame(sym_ctx, sym_frame), &info) < 0) exception(errno);
                    if (read_reg_value(info, reg_def, &addr) < 0) exception(errno);
                    range = elf_find_unit(sym_ctx, addr, addr, &rt_addr);
                    if (range != NULL) find_by_addr_in_unit(
                        get_dwarf_children(range->mUnit->mObject),
                        0, rt_addr - range->mAddr, addr, &caller);
                    if (caller != NULL && caller->obj != NULL) {
                        ObjectInfo * l = get_dwarf_children(caller->obj);
                        while (l != NULL) {
                            U8_T call_addr = 0;
                            if (l->mTag == TAG_GNU_call_site && get_num_prop(l, AT_low_pc, &call_addr)) {
                                call_addr += rt_addr - range->mAddr;
                                if (call_addr == addr) {
                                    /*
                                    clear_trap(&trap);
                                    return 0;
                                    */
                                }
                            }
                            l = l->mSibling;
                        }
                    }
                }
                exception(ERR_SYM_NOT_FOUND);
            }
        }
#endif
        if (map_to_sym_table(obj, &s)) return get_symbol_value(s, value, size, big_endian);
        set_errno(ERR_OTHER, "No object location or value info found in DWARF data");
        return -1;
    }
    if (sym->tbl != NULL) {
        ELF_SymbolInfo info;
        unpack_elf_symbol_info(sym->tbl, sym->index, &info);
        switch (info.type) {
        case STT_OBJECT:
        case STT_FUNC:
            set_errno(ERR_OTHER, "Symbol represents an address");
            return -1;
        }
        if (info.sym_section->file->elf64) {
            static U8_T buf = 0;
            buf = info.value;
            *value = &buf;
            *size = 8;
        }
        else {
            static U4_T buf = 0;
            buf = (U4_T)info.value;
            *value = &buf;
            *size = 4;
        }
        *big_endian = big_endian_host();
        return 0;
    }
    set_errno(ERR_OTHER, "Symbol does not have a value");
    return -1;
}

static int calc_member_offset(ObjectInfo * type, ObjectInfo * member, ContextAddress * offs) {
    PropertyValue v;
    ObjectInfo * obj = NULL;
    if (member->mParent == type) {
        dwarf_expression_obj_addr = 0;
        read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, member, AT_data_member_location, &v);
        *offs = (ContextAddress)get_numeric_property_value(&v);
        return 1;
    }
    obj = get_dwarf_children(type);
    while (obj != NULL) {
        if (obj->mTag == TAG_inheritance && calc_member_offset(obj->mType, member, offs)) {
            dwarf_expression_obj_addr = 0;
            read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_data_member_location, &v);
            *offs += (ContextAddress)get_numeric_property_value(&v);
            return 1;
        }
        obj = obj->mSibling;
    }
    return 0;
}

static LocationInfo * location_info = NULL;
static LocationExpressionState * location_command_state = NULL;

static void dwarf_location_operation(uint8_t op) {
    str_fmt_exception(ERR_UNSUPPORTED, "Unsupported location expression op 0x%02x", op);
}

static int dwarf_location_callback(LocationExpressionState * state) {
    location_command_state = state;
    state->client_op = dwarf_location_operation;
    return evaluate_vm_expression(state);
}

static LocationExpressionCommand * add_location_command(int op) {
    LocationExpressionCommand * cmd = NULL;
    if (location_info->cmds_cnt >= location_info->cmds_max) {
        location_info->cmds_max += 4;
        location_info->cmds = (LocationExpressionCommand *)tmp_realloc(location_info->cmds,
            sizeof(LocationExpressionCommand) * location_info->cmds_max);
    }
    cmd = location_info->cmds + location_info->cmds_cnt++;
    memset(cmd, 0, sizeof(LocationExpressionCommand));
    cmd->cmd = op;
    return cmd;
}

static LocationExpressionCommand * add_dwarf_location_command(PropertyValue * v) {
    DWARFExpressionInfo info;
    LocationExpressionCommand * cmd = add_location_command(SFT_CMD_LOCATION);

    dwarf_find_expression(v, sym_ip, &info);
    dwarf_transform_expression(sym_ctx, sym_ip, &info);
    location_info->addr = info.code_addr;
    location_info->size = info.code_size;
    cmd->args.loc.code_addr = info.expr_addr;
    cmd->args.loc.code_size = info.expr_size;
    cmd->args.loc.reg_id_scope = v->mObject->mCompUnit->mRegIdScope;
    cmd->args.loc.addr_size = v->mObject->mCompUnit->mDesc.mAddressSize;
    cmd->args.loc.func = dwarf_location_callback;
    return cmd;
}

int get_location_info(const Symbol * sym, LocationInfo ** info) {
    ObjectInfo * obj = sym->obj;

    assert(sym->magic == SYMBOL_MAGIC);
    *info = location_info = (LocationInfo *)tmp_alloc_zero(sizeof(LocationInfo));

    if (sym->has_address) {
        add_location_command(SFT_CMD_NUMBER)->args.num = sym->address;
        return 0;
    }

    if (is_array_type_pseudo_symbol(sym) ||
        is_cardinal_type_pseudo_symbol(sym) ||
        is_constant_pseudo_symbol(sym)) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }

    if (unpack(sym) < 0) return -1;

    if (obj != NULL) {
        Trap trap;
        PropertyValue v;
        if (obj->mTag == TAG_ptr_to_member_type) {
            if (set_trap(&trap)) {
                read_dwarf_object_property(sym_ctx, sym_frame, obj, AT_use_location, &v);
                add_location_command(SFT_CMD_ARG)->args.arg_no = 1;
                add_location_command(SFT_CMD_ARG)->args.arg_no = 0;
                add_dwarf_location_command(&v);
                clear_trap(&trap);
                return 0;
            }
            else {
                if (errno != ERR_SYM_NOT_FOUND) set_errno(errno, "Cannot evaluate member location expression");
                else set_errno(ERR_OTHER, "Member location info not avaiable");
                return -1;
            }
        }
        if (obj->mTag == TAG_member || obj->mTag == TAG_inheritance) {
            if (set_trap(&trap)) {
                read_dwarf_object_property(sym_ctx, sym_frame, obj, AT_data_member_location, &v);
                switch (v.mForm) {
                case FORM_DATA1     :
                case FORM_DATA4     :
                case FORM_DATA8     :
                case FORM_SDATA     :
                case FORM_UDATA     :
                    add_location_command(SFT_CMD_ARG)->args.arg_no = 0;
                    add_location_command(SFT_CMD_NUMBER)->args.num = get_numeric_property_value(&v);
                    add_location_command(SFT_CMD_ADD);
                    break;
                case FORM_BLOCK1    :
                case FORM_BLOCK2    :
                case FORM_BLOCK4    :
                case FORM_BLOCK     :
                    add_location_command(SFT_CMD_ARG)->args.arg_no = 0;
                    add_dwarf_location_command(&v);
                    break;
                }
                clear_trap(&trap);
                return 0;
            }
            else {
                if (errno != ERR_SYM_NOT_FOUND) set_errno(errno, "Cannot evaluate member location expression");
                else set_errno(ERR_OTHER, "Member location info not avaiable");
                return -1;
            }
        }
        {
            U8_T addr = 0;
            Symbol * s = NULL;
            if (set_trap(&trap)) {
                read_dwarf_object_property(sym_ctx, sym_frame, obj, AT_location, &v);
                add_dwarf_location_command(&v);
                clear_trap(&trap);
                return 0;
            }
            else if (errno != ERR_SYM_NOT_FOUND) {
                set_errno(errno, "Cannot evaluate location expression");
                return -1;
            }
            if (get_num_prop(obj, AT_low_pc, &addr)) {
                add_location_command(SFT_CMD_NUMBER)->args.num = addr;
                return 0;
            }
            if (get_error_code(errno) != ERR_SYM_NOT_FOUND) return -1;
            if (map_to_sym_table(obj, &s)) return get_location_info(s, info);
            set_errno(ERR_OTHER, "No object location info found in DWARF data");
            return -1;
        }
    }

    if (sym->tbl != NULL) {
        ELF_SymbolInfo info;
        ContextAddress addr = 0;
        unpack_elf_symbol_info(sym->tbl, sym->index, &info);
        if (syminfo2address(sym_ctx, &info, &addr) < 0) return -1;
        add_location_command(SFT_CMD_NUMBER)->args.num = addr;
        return 0;
    }

    set_errno(ERR_OTHER, "Symbol does not have a memory address");
    return -1;
}

int get_symbol_address(const Symbol * sym, ContextAddress * address) {
    ObjectInfo * obj = sym->obj;

    assert(sym->magic == SYMBOL_MAGIC);
    if (sym->has_address) {
        *address = sym->address;
        return 0;
    }
    if (is_array_type_pseudo_symbol(sym) ||
        is_cardinal_type_pseudo_symbol(sym) ||
        is_constant_pseudo_symbol(sym)) {
        errno = ERR_INV_CONTEXT;
        return -1;
    }
    if (unpack(sym) < 0) return -1;
    if (obj != NULL && (obj->mFlags & DOIF_external) == 0 && sym->var != NULL) {
        /* The symbol represents a member of a class instance */
        Trap trap;
        PropertyValue v;
        ContextAddress base = 0;
        ContextAddress offs = 0;
        ObjectInfo * type = get_original_type(sym->var);
        if (!set_trap(&trap)) {
            if (errno == ERR_SYM_NOT_FOUND) set_errno(ERR_OTHER, "Location attribute not found");
            set_errno(errno, "Cannot evaluate location of 'this' pointer");
            return -1;
        }
        if ((type->mTag != TAG_pointer_type && type->mTag != TAG_mod_pointer) || type->mType == NULL) exception(ERR_INV_CONTEXT);
        read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, sym->var, AT_location, &v);
        base = (ContextAddress)read_cardinal_object_value(&v);
        type = get_original_type(type->mType);
        if (!calc_member_offset(type, obj, &offs)) exception(ERR_INV_CONTEXT);
        clear_trap(&trap);
        *address = base + offs;
        return 0;
    }
    if (obj != NULL && obj->mTag != TAG_member && obj->mTag != TAG_inheritance) {
        U8_T v;
        Symbol * s = NULL;
        if (get_num_prop(obj, AT_location, &v)) {
            *address = (ContextAddress)v;
            return 0;
        }
        if (get_error_code(errno) != ERR_SYM_NOT_FOUND) return -1;
        if (get_num_prop(obj, AT_low_pc, &v)) {
            *address = (ContextAddress)v;
            return 0;
        }
        if (get_error_code(errno) != ERR_SYM_NOT_FOUND) return -1;
        if (map_to_sym_table(obj, &s)) return get_symbol_address(s, address);
        set_errno(ERR_OTHER, "No object location info found in DWARF data");
        return -1;
    }
    if (sym->tbl != NULL) {
        ELF_SymbolInfo info;
        unpack_elf_symbol_info(sym->tbl, sym->index, &info);
        return syminfo2address(sym_ctx, &info, address);
    }

    set_errno(ERR_OTHER, "Symbol does not have a memory address");
    return -1;
}

int get_symbol_register(const Symbol * sym, Context ** ctx, int * frame, RegisterDefinition ** reg) {
    ObjectInfo * obj = sym->obj;

    assert(sym->magic == SYMBOL_MAGIC);
    if (!sym->has_address && obj != NULL && obj->mTag != TAG_member && obj->mTag != TAG_inheritance) {
        Trap trap;
        if (unpack(sym) < 0) return -1;
        if (set_trap(&trap)) {
            PropertyValue v;
            read_and_evaluate_dwarf_object_property(sym_ctx, sym_frame, obj, AT_location, &v);
            *ctx = sym_ctx;
            *frame = sym_frame;
            if (v.mPieceCnt == 1 && v.mPieces[0].reg != NULL && v.mPieces[0].bit_size == 0) {
                *reg = v.mPieces[0].reg;
            }
            else {
                *reg = NULL;
            }
            clear_trap(&trap);
            return 0;
        }
    }

    set_errno(ERR_OTHER, "Symbol is not located in a register");
    return -1;
}

int get_symbol_flags(const Symbol * sym, SYM_FLAGS * flags) {
    U8_T v = 0;
    ObjectInfo * obj = sym->obj;
    *flags = 0;
    assert(sym->magic == SYMBOL_MAGIC);
    if (sym->base || is_cardinal_type_pseudo_symbol(sym)) return 0;
    if (unpack(sym) < 0) return -1;
    if (obj != NULL) {
        if (obj->mFlags & DOIF_external) *flags |= SYM_FLAG_EXTERNAL;
        if (obj->mFlags & DOIF_artificial) *flags |= SYM_FLAG_ARTIFICIAL;
        if (obj->mFlags & DOIF_private) *flags |= SYM_FLAG_PRIVATE;
        if (obj->mFlags & DOIF_protected) *flags |= SYM_FLAG_PROTECTED;
        if (obj->mFlags & DOIF_public) *flags |= SYM_FLAG_PUBLIC;
        switch (obj->mTag) {
        case TAG_subrange_type:
            *flags |= SYM_FLAG_SUBRANGE_TYPE;
            break;
        case TAG_packed_type:
            *flags |= SYM_FLAG_PACKET_TYPE;
            break;
        case TAG_const_type:
            *flags |= SYM_FLAG_CONST_TYPE;
            break;
        case TAG_volatile_type:
            *flags |= SYM_FLAG_VOLATILE_TYPE;
            break;
        case TAG_restrict_type:
            *flags |= SYM_FLAG_RESTRICT_TYPE;
            break;
        case TAG_shared_type:
            *flags |= SYM_FLAG_SHARED_TYPE;
            break;
        case TAG_typedef:
            *flags |= SYM_FLAG_TYPEDEF;
            break;
        case TAG_template_type_param:
            *flags |= SYM_FLAG_TYPE_PARAMETER;
            break;
        case TAG_reference_type:
        case TAG_mod_reference:
            *flags |= SYM_FLAG_REFERENCE;
            break;
        case TAG_union_type:
            *flags |= SYM_FLAG_UNION_TYPE;
            break;
        case TAG_class_type:
            *flags |= SYM_FLAG_CLASS_TYPE;
            break;
        case TAG_structure_type:
            *flags |= SYM_FLAG_STRUCT_TYPE;
            break;
        case TAG_enumeration_type:
            *flags |= SYM_FLAG_ENUM_TYPE;
            break;
        case TAG_interface_type:
            *flags |= SYM_FLAG_INTERFACE_TYPE;
            break;
        case TAG_unspecified_parameters:
            *flags |= SYM_FLAG_PARAMETER;
            *flags |= SYM_FLAG_VARARG;
            break;
        case TAG_formal_parameter:
        case TAG_variable:
        case TAG_constant:
        case TAG_base_type:
            if (obj->mTag == TAG_formal_parameter) {
                *flags |= SYM_FLAG_PARAMETER;
                if (get_num_prop(obj, AT_is_optional, &v) && v != 0) *flags |= SYM_FLAG_OPTIONAL;
            }
            if (get_num_prop(obj, AT_endianity, &v)) {
                if (v == DW_END_big) *flags |= SYM_FLAG_BIG_ENDIAN;
                if (v == DW_END_little) *flags |= SYM_FLAG_LITTLE_ENDIAN;
            }
            break;
        }
    }
    if (obj != NULL && sym->sym_class == SYM_CLASS_TYPE && !(*flags & (SYM_FLAG_BIG_ENDIAN|SYM_FLAG_LITTLE_ENDIAN))) {
        *flags |= obj->mCompUnit->mFile->big_endian ? SYM_FLAG_BIG_ENDIAN : SYM_FLAG_LITTLE_ENDIAN;
    }
    return 0;
}

int get_array_symbol(const Symbol * sym, ContextAddress length, Symbol ** ptr) {
    assert(sym->magic == SYMBOL_MAGIC);
    assert(sym->sym_class == SYM_CLASS_TYPE);
    assert(sym->frame == STACK_NO_FRAME);
    assert(sym->ctx == context_get_group(sym->ctx, CONTEXT_GROUP_SYMBOLS));
    *ptr = alloc_symbol();
    (*ptr)->ctx = sym->ctx;
    (*ptr)->frame = STACK_NO_FRAME;
    (*ptr)->sym_class = SYM_CLASS_TYPE;
    (*ptr)->base = (Symbol *)sym;
    (*ptr)->length = length;
    return 0;
}

int get_funccall_info(const Symbol * func,
        const Symbol ** args, unsigned args_cnt, FunctionCallInfo ** res) {
    if (func->obj != NULL) {
        FunctionCallInfo * info = (FunctionCallInfo *)tmp_alloc_zero(sizeof(FunctionCallInfo));
        info->ctx = func->ctx;
        info->func = func;
        info->scope = func->obj->mCompUnit->mRegIdScope;
        info->args_cnt = args_cnt;
        info->args = args;
        if (get_function_call_location_expression(info) < 0) return -1;
        *res = info;
        return 0;
    }
    set_errno(ERR_OTHER, "Func call injection info not available");
    return -1;
}

#endif /* SERVICE_Symbols && ENABLE_ELF */
