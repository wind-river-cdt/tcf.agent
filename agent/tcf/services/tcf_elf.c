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
 * This module implements reading and caching of ELF files.
 */

#if defined(__GNUC__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
#endif

#include <tcf/config.h>

#if ENABLE_ELF

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/events.h>
#include <tcf/framework/trace.h>
#include <tcf/services/tcf_elf.h>
#include <tcf/services/memorymap.h>
#include <tcf/services/dwarfcache.h>
#include <tcf/services/pathmap.h>

#if defined(_WRS_KERNEL)
#elif defined(_MSC_VER)
#  define USE_MMAP
#elif defined(_WIN32)
#else
#  include <sys/mman.h>
#  define USE_MMAP
#endif

#define MIN_FILE_AGE 3
#define MAX_FILE_AGE 60
#define MAX_FILE_CNT 100

typedef struct FileINode {
    struct FileINode * next;
    char * name;
    ino_t ino;
} FileINode;

static ELF_File * files = NULL;
static FileINode * inodes = NULL;
static ELFCloseListener * listeners = NULL;
static unsigned listeners_cnt = 0;
static unsigned listeners_max = 0;
static int elf_cleanup_posted = 0;
static ino_t elf_ino_cnt = 0;

typedef struct ElfListState {
    Context * ctx;
    unsigned pos;
    MemoryMap map;
    struct ElfListState * next;
} ElfListState;

static ElfListState * elf_list_state = NULL;

#if ENABLE_DebugContext

static MemoryMap elf_map;

#endif

static ELF_File * find_open_file_by_name(const char * name);

void elf_add_close_listener(ELFCloseListener listener) {
    if (listeners_cnt >= listeners_max) {
        listeners_max = listeners_max == 0 ? 16 : listeners_max * 2;
        listeners = (ELFCloseListener *)loc_realloc(listeners, sizeof(ELFCloseListener) * listeners_max);
    }
    listeners[listeners_cnt++] = listener;
}

static void elf_dispose(ELF_File * file) {
    unsigned n;
    trace(LOG_ELF, "Dispose ELF file cache %s", file->name);
    for (n = 0; n < listeners_cnt; n++) {
        listeners[n](file);
    }
    if (file->fd >= 0) close(file->fd);
    if (file->sections != NULL) {
        for (n = 0; n < file->section_cnt; n++) {
            ELF_Section * s = file->sections + n;
#if !defined(USE_MMAP)
            loc_free(s->data);
#elif defined(_WIN32)
            if (s->mmap_addr == NULL) loc_free(s->data);
            else UnmapViewOfFile(s->mmap_addr);
#else
            if (s->mmap_addr == NULL) loc_free(s->data);
            else munmap(s->mmap_addr, s->mmap_size);
#endif
            loc_free(s->sym_addr_table);
            loc_free(s->sym_names_hash);
            loc_free(s->sym_names_next);
        }
        loc_free(file->sections);
    }
#if defined(_WIN32)
    if (file->mmap_handle != NULL) CloseHandle(file->mmap_handle);
#endif
    for (n = 0; n < file->names_cnt; n++) {
        loc_free(file->names[n]);
    }
    loc_free(file->names);
    release_error_report(file->error);
    loc_free(file->pheaders);
    loc_free(file->str_pool);
    loc_free(file->debug_info_file_name);
    loc_free(file->name);
    loc_free(file);
}

static void free_elf_list_state(ElfListState * state) {
    loc_free(state->map.regions);
    loc_free(state);
}

static void add_file_name(ELF_File * file, const char * name) {
    if (file->names_cnt >= file->names_max) {
        file->names_max += 8;
        file->names = (char **)loc_realloc(file->names, sizeof(char *) * file->names_max);
    }
    file->names[file->names_cnt++] = loc_strdup(name);
}

static int file_name_equ(ELF_File * file, const char * name) {
    unsigned i;
    if (name == NULL) return 0;
    if (strcmp(file->name, name) == 0) return 1;
    for (i = 0; i < file->names_cnt; i++) {
        if (strcmp(file->names[i], name) == 0) return 1;
    }
    return 0;
}

#if SERVICE_MemoryMap
static int is_file_mapped_by_mem_map(ELF_File * file, MemoryMap * map) {
    unsigned i;
    for (i = 0; i < map->region_cnt; i++) {
        MemoryRegion * r = map->regions + i;
        if (file->dev == r->dev && file->ino == r->ino) return 1;
        if (r->dev != 0 && r->dev != file->dev) continue;
        if (r->ino != 0 && r->ino != file->ino) continue;
        if (file_name_equ(file, r->file_name)) return 1;
    }
    return 0;
}

static int is_file_mapped(ELF_File * file) {
    int res = 0;
    LINK * l = context_root.next;
    while (!res && l != &context_root) {
        MemoryMap * client_map = NULL;
        MemoryMap * target_map = NULL;
        Context * c = ctxl2ctxp(l);
        l = l->next;
        if (c->mem_access == 0 || c->exited) continue;
        if (c != context_get_group(c, CONTEXT_GROUP_PROCESS)) continue;
        if (memory_map_get(c, &client_map, &target_map) < 0) continue;
        res = is_file_mapped_by_mem_map(file, client_map) || is_file_mapped_by_mem_map(file, target_map);
    }
    return res;
}
#endif /* SERVICE_MemoryMap */

static void elf_cleanup_event(void * arg) {
    ELF_File * prev = NULL;
    ELF_File * file = NULL;
    unsigned file_cnt = 0;
    unsigned max_file_age = MAX_FILE_AGE;
    static unsigned event_cnt = 0;

    assert(elf_cleanup_posted);
    elf_cleanup_posted = 0;

    if (event_cnt % 5 == 0) {
        file = files;
        while (file != NULL) {
            struct stat st;
            if (file->fd >= 0 && !file->mtime_changed &&
                    fstat(file->fd, &st) == 0 && file->mtime != st.st_mtime) {
                file->mtime_changed = 1;
            }
            file = file->next;
            file_cnt++;
        }
    }

    if (file_cnt > MAX_FILE_AGE + MAX_FILE_CNT - MIN_FILE_AGE) {
        max_file_age = MIN_FILE_AGE;
    }
    else if (file_cnt > MAX_FILE_CNT) {
        max_file_age = MAX_FILE_AGE + MAX_FILE_CNT - file_cnt;
    }

    file = files;
    while (file != NULL) {
        file->age++;
#if SERVICE_MemoryMap
        if (!file->debug_info_file && file->age % max_file_age / 2 == 0 && is_file_mapped(file)) {
            file->age = 0;
            if (file->debug_info_file_name) {
                find_open_file_by_name(file->debug_info_file_name);
            }
        }
#endif
        if (file->age > max_file_age || (file->age > MIN_FILE_AGE && list_is_empty(&context_root))) {
            ELF_File * next = file->next;
            elf_dispose(file);
            file = next;
            if (prev != NULL) prev->next = file;
            else files = file;
        }
        else {
            prev = file;
            file = file->next;
        }
    }

    if (files != NULL) {
        post_event_with_delay(elf_cleanup_event, NULL, 1000000);
        elf_cleanup_posted = 1;
    }
    else if (list_is_empty(&context_root)) {
        while (inodes != NULL) {
            FileINode * n = inodes;
            inodes = n->next;
            loc_free(n->name);
            loc_free(n);
        }
    }

    while (elf_list_state != NULL) {
        ElfListState * state = elf_list_state;
        elf_list_state = state->next;
        free_elf_list_state(state);
    }

    event_cnt++;
}

static ino_t add_ino(const char * fnm, ino_t ino) {
    FileINode * n = (FileINode *)loc_alloc_zero(sizeof(*n));
    n->next = inodes;
    n->name = loc_strdup(fnm);
    n->ino = ino;
    inodes = n;
    return ino;
}

static ino_t elf_ino(const char * fnm) {
    /*
     * Number of the information node (the inode) for the file is used as file ID.
     * Since some file systems don't support inodes, this function is used in such cases
     * to generate virtual inode numbers to be used as file IDs.
     */
    char * abs = NULL;
    FileINode * n = inodes;
    while (n != NULL) {
        if (strcmp(n->name, fnm) == 0) return n->ino;
        n = n->next;
    }
    abs = canonicalize_file_name(fnm);
    if (abs == NULL) return add_ino(fnm, 0);
    n = inodes;
    while (n != NULL) {
        if (strcmp(n->name, abs) == 0) {
            free(abs);
            return add_ino(fnm, n->ino);
        }
        n = n->next;
    }
    if (elf_ino_cnt == 0) elf_ino_cnt++;
    add_ino(fnm, elf_ino_cnt);
    if (strcmp(abs, fnm) != 0) add_ino(abs, elf_ino_cnt);
    free(abs);
    return elf_ino_cnt++;
}

static ELF_File * find_open_file_by_name(const char * name) {
    ELF_File * prev = NULL;
    ELF_File * file = files;
    while (file != NULL) {
        if (file_name_equ(file, name)) {
            if (prev != NULL) {
                prev->next = file->next;
                file->next = files;
                files = file;
            }
            file->age = 0;
            return file;
        }
        prev = file;
        file = file->next;
    }
    return NULL;
}

static ELF_File * find_open_file_by_inode(dev_t dev, ino_t ino, int64_t mtime) {
    ELF_File * prev = NULL;
    ELF_File * file = files;
    while (file != NULL) {
        if (file->dev == dev && file->ino == ino &&
            (mtime ? file->mtime == mtime : !file->mtime_changed)) {
            if (prev != NULL) {
                prev->next = file->next;
                file->next = files;
                files = file;
            }
            file->age = 0;
            return file;
        }
        prev = file;
        file = file->next;
    }
    return NULL;
}

void swap_bytes(void * buf, size_t size) {
    size_t i, j, n;
    char * p = (char *)buf;
    n = size >> 1;
    for (i = 0, j = size - 1; i < n; i++, j--) {
        char x = p[i];
        p[i] = p[j];
        p[j] = x;
    }
}

static char * get_debug_info_file_name(ELF_File * file, int * error) {
    unsigned idx;

    for (idx = 1; idx < file->section_cnt; idx++) {
        ELF_Section * sec = file->sections + idx;
        if (sec->size == 0) continue;
        if (sec->type == SHT_NOTE && (sec->flags & SHF_ALLOC)) {
            unsigned offs = 0;
            if (elf_load(sec) < 0) {
                *error = errno;
                return NULL;
            }
            while (offs < sec->size) {
                U4_T name_sz = *(U4_T *)((U1_T *)sec->data + offs);
                U4_T desc_sz = *(U4_T *)((U1_T *)sec->data + offs + 4);
                U4_T type = *(U4_T *)((U1_T *)sec->data + offs + 8);
                char * name = NULL;
                offs += 12;
                if (file->byte_swap) {
                    SWAP(name_sz);
                    SWAP(desc_sz);
                    SWAP(type);
                }
                name = (char *)((U1_T *)sec->data + offs);
                offs += name_sz;
                while (offs % 4 != 0) offs++;
                if (type == 3 && strcmp(name, "GNU") == 0) {
                    char fnm[FILE_PATH_SIZE];
                    char * lnm = fnm;
                    struct stat buf;
                    char id[64];
                    size_t id_size = 0;
                    U1_T * desc = (U1_T *)sec->data + offs;
                    U4_T i = 0;
                    while (i < desc_sz) {
                        U1_T j = (desc[i] >> 4) & 0xf;
                        U1_T k = desc[i++] & 0xf;
                        id[id_size++] = j < 10 ? '0' + j : 'a' + j - 10;
                        id[id_size++] = k < 10 ? '0' + k : 'a' + k - 10;
                    }
                    id[id_size++] = 0;
                    trace(LOG_ELF, "Found GNU build ID %s", id);
                    snprintf(fnm, sizeof(fnm), "/usr/lib/debug/.build-id/%.2s/%s.debug", id, id + 2);
#if SERVICE_PathMap
                    lnm = apply_path_map(NULL, NULL, lnm, PATH_MAP_TO_LOCAL);
#endif
                    if (stat(lnm, &buf) == 0) return loc_strdup(lnm);
                    snprintf(fnm, sizeof(fnm), "%s.debug", file->name);
#if SERVICE_PathMap
                    lnm = apply_path_map(NULL, NULL, lnm, PATH_MAP_TO_LOCAL);
#endif
                    if (stat(lnm, &buf) == 0) return loc_strdup(lnm);
                }
                offs += desc_sz;
                while (offs % 4 != 0) offs++;
            }
        }
        else if (sec->name != NULL && strcmp(sec->name, ".gnu_debuglink") == 0) {
            if (elf_load(sec) < 0) {
                *error = errno;
                return NULL;
            }
            else {
                /* TODO: check debug info CRC */
                char fnm[FILE_PATH_SIZE];
                char * lnm = fnm;
                struct stat buf;
                char * name = (char *)sec->data;
                int l = (int)strlen(file->name);
                while (l > 0 && file->name[l - 1] != '/' && file->name[l - 1] != '\\') l--;
                if (strcmp(file->name + l, name) != 0) {
                    snprintf(fnm, sizeof(fnm), "%.*s%s", l, file->name, name);
                    if (stat(fnm, &buf) == 0) return loc_strdup(fnm);
                }
                snprintf(fnm, sizeof(fnm), "%.*s.debug/%s", l, file->name, name);
                if (stat(fnm, &buf) == 0) return loc_strdup(fnm);
                snprintf(fnm, sizeof(fnm), "/usr/lib/debug%.*s%s", l, file->name, name);
#if SERVICE_PathMap
                lnm = apply_path_map(NULL, NULL, lnm, PATH_MAP_TO_LOCAL);
#endif
                if (stat(lnm, &buf) == 0) return loc_strdup(lnm);
            }
        }
    }
    return NULL;
}

static int is_debug_info_file(ELF_File * file) {
    unsigned i = 0;
    size_t l = strlen(file->name);
    if (l > 6 && strcmp(file->name + l - 6, ".debug") == 0) return 1;
    if (file->section_cnt == 0) return 0;
    for (i = 1; i < file->section_cnt - 1; i++) {
        ELF_Section * sec = file->sections + i;
        if (sec->size > 0 && sec->type == SHT_NOBITS && sec->name != NULL) {
            if (strcmp(sec->name, ".text") == 0) return 1;
            if (strcmp(sec->name, ".data") == 0) return 1;
        }
    }
    return 0;
}

static void create_symbol_names_hash(ELF_Section * tbl);

static ELF_File * create_elf_cache(const char * file_name) {
    struct stat st;
    int error = 0;
    ELF_File * file = NULL;
    unsigned str_index = 0;
    char * real_name = NULL;

    file = find_open_file_by_name(file_name);
    if (file != NULL) return file;

    if (stat(file_name, &st) < 0) {
        error = errno;
        memset(&st, 0, sizeof(st));
    }
    else if (st.st_ino == 0) {
        st.st_ino = elf_ino(file_name);
    }

    if (!error) {
        file = find_open_file_by_inode(st.st_dev, st.st_ino, st.st_mtime);
        if (file != NULL) {
            add_file_name(file, file_name);
            return file;
        }
    }

    trace(LOG_ELF, "Create ELF file cache %s", file_name);

    file = (ELF_File *)loc_alloc_zero(sizeof(ELF_File));
    file->fd = -1;
    file->dev = st.st_dev;
    file->ino = st.st_ino;
    file->mtime = st.st_mtime;
    file->size = st.st_size;

    if (error == 0) real_name = canonicalize_file_name(file_name);

    if (real_name == NULL || strcmp(real_name, file_name) == 0) {
        file->name = loc_strdup(file_name);
    }
    else {
        file->name = loc_strdup(real_name);
        add_file_name(file, file_name);
    }

    if (error == 0 && (file->fd = open(file->name, O_RDONLY | O_BINARY, 0)) < 0) error = errno;

    if (error == 0) {
        Elf32_Ehdr hdr;
        int symtab_found;
        ELF_Section * dynsym_section;

        memset(&hdr, 0, sizeof(hdr));
        if (read(file->fd, (char *)&hdr, sizeof(hdr)) < 0) error = errno;
        if (error == 0 && strncmp((char *)hdr.e_ident, ELFMAG, SELFMAG) != 0) {
            error = set_errno(ERR_INV_FORMAT, "Unsupported ELF identification code");
        }
        if (error == 0) {
            if (hdr.e_ident[EI_DATA] == ELFDATA2LSB) {
                file->big_endian = 0;
            }
            else if (hdr.e_ident[EI_DATA] == ELFDATA2MSB) {
                file->big_endian = 1;
            }
            else {
                error = set_errno(ERR_INV_FORMAT, "Invalid ELF data encoding ID");
            }
            file->byte_swap = file->big_endian != big_endian_host();
        }

        symtab_found = 0;
        dynsym_section = NULL;
        if (error != 0) {
            /* Nothing */
        }
        else if (hdr.e_ident[EI_CLASS] == ELFCLASS32) {
            if (file->byte_swap) {
                SWAP(hdr.e_type);
                SWAP(hdr.e_machine);
                SWAP(hdr.e_version);
                SWAP(hdr.e_entry);
                SWAP(hdr.e_phoff);
                SWAP(hdr.e_shoff);
                SWAP(hdr.e_flags);
                SWAP(hdr.e_ehsize);
                SWAP(hdr.e_phentsize);
                SWAP(hdr.e_phnum);
                SWAP(hdr.e_shentsize);
                SWAP(hdr.e_shnum);
                SWAP(hdr.e_shstrndx);
            }
            file->type = hdr.e_type;
            file->machine = hdr.e_machine;
            file->os_abi = hdr.e_ident[EI_OSABI];
            if (error == 0 && hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN && hdr.e_type != ET_REL) {
                error = set_errno(ERR_INV_FORMAT, "Invalid ELF type ID");
            }
            if (error == 0 && hdr.e_version != EV_CURRENT) {
                error = set_errno(ERR_INV_FORMAT, "Unsupported ELF version");
            }
            if (error == 0 && hdr.e_shoff == 0) {
                error = set_errno(ERR_INV_FORMAT, "Invalid section header table's file offset");
            }
            if (error == 0 && lseek(file->fd, hdr.e_shoff, SEEK_SET) == (off_t)-1) error = errno;
            if (error == 0) {
                unsigned cnt = 0;
                file->sections = (ELF_Section *)loc_alloc_zero(sizeof(ELF_Section) * hdr.e_shnum);
                file->section_cnt = hdr.e_shnum;
                while (error == 0 && cnt < hdr.e_shnum) {
                    int rd = 0;
                    Elf32_Shdr shdr;
                    memset(&shdr, 0, sizeof(shdr));
                    if (error == 0 && sizeof(shdr) < hdr.e_shentsize) error = ERR_INV_FORMAT;
                    if (error == 0 && (rd = read(file->fd, (char *)&shdr, hdr.e_shentsize)) < 0) error = errno;
                    if (error == 0 && rd != hdr.e_shentsize) error = ERR_INV_FORMAT;
                    if (error == 0) {
                        ELF_Section * sec = file->sections + cnt;
                        if (file->byte_swap) {
                            SWAP(shdr.sh_name);
                            SWAP(shdr.sh_type);
                            SWAP(shdr.sh_flags);
                            SWAP(shdr.sh_addr);
                            SWAP(shdr.sh_offset);
                            SWAP(shdr.sh_size);
                            SWAP(shdr.sh_link);
                            SWAP(shdr.sh_info);
                            SWAP(shdr.sh_addralign);
                            SWAP(shdr.sh_entsize);
                        }
                        sec->file = file;
                        sec->index = cnt;
                        sec->name_offset = shdr.sh_name;
                        sec->type = shdr.sh_type;
                        sec->alignment = (U4_T)shdr.sh_addralign;
                        sec->offset = shdr.sh_offset;
                        sec->size = shdr.sh_size;
                        sec->flags = shdr.sh_flags;
                        sec->addr = shdr.sh_addr;
                        sec->link = shdr.sh_link;
                        sec->info = shdr.sh_info;
                        sec->entsize = shdr.sh_entsize;
                        if (sec->type == SHT_SYMTAB) {
                            sec->sym_count = (unsigned)(sec->size / sizeof(Elf32_Sym));
                            symtab_found = 1;
                        }
                        else if (sec->type == SHT_DYNSYM) {
                            assert(dynsym_section == NULL);
                            sec->sym_count = (unsigned)(sec->size / sizeof(Elf32_Sym));
                            dynsym_section = sec;
                        }
                        cnt++;
                    }
                }
            }
            if (error == 0 && lseek(file->fd, hdr.e_phoff, SEEK_SET) == (off_t)-1) error = errno;
            if (error == 0) {
                unsigned cnt = 0;
                file->pheaders = (ELF_PHeader *)loc_alloc_zero(sizeof(ELF_PHeader) * hdr.e_phnum);
                file->pheader_cnt = hdr.e_phnum;
                while (error == 0 && cnt < hdr.e_phnum) {
                    int rd = 0;
                    Elf32_Phdr phdr;
                    memset(&phdr, 0, sizeof(phdr));
                    if (error == 0 && sizeof(phdr) < hdr.e_phentsize) error = ERR_INV_FORMAT;
                    if (error == 0 && (rd = read(file->fd, (char *)&phdr, hdr.e_phentsize)) < 0) error = errno;
                    if (error == 0 && rd != hdr.e_phentsize) error = ERR_INV_FORMAT;
                    if (error == 0) {
                        ELF_PHeader * p = file->pheaders + cnt;
                        if (file->byte_swap) {
                            SWAP(phdr.p_type);
                            SWAP(phdr.p_offset);
                            SWAP(phdr.p_vaddr);
                            SWAP(phdr.p_paddr);
                            SWAP(phdr.p_filesz);
                            SWAP(phdr.p_memsz);
                            SWAP(phdr.p_flags);
                            SWAP(phdr.p_align);
                        }
                        p->type = phdr.p_type;
                        p->offset = phdr.p_offset;
                        p->address = phdr.p_vaddr;
                        p->physical_address = phdr.p_paddr;
                        p->file_size = phdr.p_filesz;
                        p->mem_size = phdr.p_memsz;
                        p->flags = phdr.p_flags;
                        p->align = phdr.p_align;
                        cnt++;
                    }
                }
            }
            str_index = hdr.e_shstrndx;
        }
        else if (hdr.e_ident[EI_CLASS] == ELFCLASS64) {
            Elf64_Ehdr hdr;
            file->elf64 = 1;
            memset(&hdr, 0, sizeof(hdr));
            if (error == 0 && lseek(file->fd, 0, SEEK_SET) == (off_t)-1) error = errno;
            if (error == 0 && read(file->fd, (char *)&hdr, sizeof(hdr)) < 0) error = errno;
            if (file->byte_swap) {
                SWAP(hdr.e_type);
                SWAP(hdr.e_machine);
                SWAP(hdr.e_version);
                SWAP(hdr.e_entry);
                SWAP(hdr.e_phoff);
                SWAP(hdr.e_shoff);
                SWAP(hdr.e_flags);
                SWAP(hdr.e_ehsize);
                SWAP(hdr.e_phentsize);
                SWAP(hdr.e_phnum);
                SWAP(hdr.e_shentsize);
                SWAP(hdr.e_shnum);
                SWAP(hdr.e_shstrndx);
            }
            file->type = hdr.e_type;
            file->machine = hdr.e_machine;
            file->os_abi = hdr.e_ident[EI_OSABI];
            if (error == 0 && hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN && hdr.e_type != ET_REL) {
                error = set_errno(ERR_INV_FORMAT, "Invalid ELF type ID");
            }
            if (error == 0 && hdr.e_version != EV_CURRENT) {
                error = set_errno(ERR_INV_FORMAT, "Unsupported ELF version");
            }
            if (error == 0 && hdr.e_shoff == 0) {
                error = set_errno(ERR_INV_FORMAT, "Invalid section header table's file offset");
            }
            if (error == 0 && lseek(file->fd, hdr.e_shoff, SEEK_SET) == (off_t)-1) error = errno;
            if (error == 0) {
                unsigned cnt = 0;
                file->sections = (ELF_Section *)loc_alloc_zero(sizeof(ELF_Section) * hdr.e_shnum);
                file->section_cnt = hdr.e_shnum;
                while (error == 0 && cnt < hdr.e_shnum) {
                    int rd = 0;
                    Elf64_Shdr shdr;
                    memset(&shdr, 0, sizeof(shdr));
                    if (error == 0 && sizeof(shdr) < hdr.e_shentsize) error = ERR_INV_FORMAT;
                    if (error == 0 && (rd = read(file->fd, (char *)&shdr, hdr.e_shentsize)) < 0) error = errno;
                    if (error == 0 && rd != hdr.e_shentsize) error = ERR_INV_FORMAT;
                    if (error == 0) {
                        ELF_Section * sec = file->sections + cnt;
                        if (file->byte_swap) {
                            SWAP(shdr.sh_name);
                            SWAP(shdr.sh_type);
                            SWAP(shdr.sh_flags);
                            SWAP(shdr.sh_addr);
                            SWAP(shdr.sh_offset);
                            SWAP(shdr.sh_size);
                            SWAP(shdr.sh_link);
                            SWAP(shdr.sh_info);
                            SWAP(shdr.sh_addralign);
                            SWAP(shdr.sh_entsize);
                        }
                        sec->file = file;
                        sec->index = cnt;
                        sec->name_offset = shdr.sh_name;
                        sec->type = shdr.sh_type;
                        sec->alignment = (U4_T)shdr.sh_addralign;
                        sec->offset = shdr.sh_offset;
                        sec->size = shdr.sh_size;
                        sec->flags = (U4_T)shdr.sh_flags;
                        sec->addr = shdr.sh_addr;
                        sec->link = shdr.sh_link;
                        sec->info = shdr.sh_info;
                        sec->entsize = (U4_T)shdr.sh_entsize;
                        if (sec->type == SHT_SYMTAB) {
                            sec->sym_count = (unsigned)(sec->size / sizeof(Elf64_Sym));
                            symtab_found = 1;
                        }
                        else if (sec->type == SHT_DYNSYM) {
                            assert(dynsym_section == NULL);
                            sec->sym_count = (unsigned)(sec->size / sizeof(Elf64_Sym));
                            dynsym_section = sec;
                        }
                        cnt++;
                    }
                }
            }
            if (error == 0 && lseek(file->fd, hdr.e_phoff, SEEK_SET) == (off_t)-1) error = errno;
            if (error == 0) {
                unsigned cnt = 0;
                file->pheaders = (ELF_PHeader *)loc_alloc_zero(sizeof(ELF_PHeader) * hdr.e_phnum);
                file->pheader_cnt = hdr.e_phnum;
                while (error == 0 && cnt < hdr.e_phnum) {
                    int rd = 0;
                    Elf64_Phdr phdr;
                    memset(&phdr, 0, sizeof(phdr));
                    if (error == 0 && sizeof(phdr) < hdr.e_phentsize) error = ERR_INV_FORMAT;
                    if (error == 0 && (rd = read(file->fd, (char *)&phdr, hdr.e_phentsize)) < 0) error = errno;
                    if (error == 0 && rd != hdr.e_phentsize) error = ERR_INV_FORMAT;
                    if (error == 0) {
                        ELF_PHeader * p = file->pheaders + cnt;
                        if (file->byte_swap) {
                            SWAP(phdr.p_type);
                            SWAP(phdr.p_offset);
                            SWAP(phdr.p_vaddr);
                            SWAP(phdr.p_paddr);
                            SWAP(phdr.p_filesz);
                            SWAP(phdr.p_memsz);
                            SWAP(phdr.p_flags);
                            SWAP(phdr.p_align);
                        }
                        p->type = phdr.p_type;
                        p->offset = phdr.p_offset;
                        p->address = phdr.p_vaddr;
                        p->physical_address = phdr.p_paddr;
                        p->file_size = phdr.p_filesz;
                        p->mem_size = phdr.p_memsz;
                        p->flags = phdr.p_flags;
                        p->align = (U4_T)phdr.p_align;
                        cnt++;
                    }
                }
            }
            str_index = hdr.e_shstrndx;
        }
        else {
            error = set_errno(ERR_INV_FORMAT, "Invalid ELF class ID");
        }
        if (error == 0 && str_index != 0 && str_index < file->section_cnt) {
            int rd = 0;
            ELF_Section * str = file->sections + str_index;
            file->str_pool = (char *)loc_alloc((size_t)str->size);
            if (str->offset == 0 || str->size == 0) error = set_errno(ERR_INV_FORMAT, "Invalid ELF string pool offset or size");
            if (error == 0 && lseek(file->fd, str->offset, SEEK_SET) == (off_t)-1) error = errno;
            if (error == 0 && (rd = read(file->fd, file->str_pool, (size_t)str->size)) < 0) error = errno;
            if (error == 0 && rd != (int)str->size) error = set_errno(ERR_INV_FORMAT, "Cannot read ELF string pool");
            if (error == 0) {
                unsigned i;
                for (i = 1; i < file->section_cnt; i++) {
                    ELF_Section * sec = file->sections + i;
                    sec->name = file->str_pool + sec->name_offset;
                }
            }
        }

        if (dynsym_section != NULL && symtab_found) dynsym_section->sym_count = 0;
    }
    if (error == 0) {
        unsigned m = 0;
        for (m = 1; m < file->section_cnt; m++) {
            ELF_Section * tbl = file->sections + m;
            if (tbl->sym_count == 0) continue;
            create_symbol_names_hash(tbl);
        }
        file->debug_info_file = is_debug_info_file(file);
        if (!file->debug_info_file) file->debug_info_file_name = get_debug_info_file_name(file, &error);
        if (file->debug_info_file_name) trace(LOG_ELF, "Debug info file found %s", file->debug_info_file_name);
    }
    if (error != 0) {
        trace(LOG_ELF, "Error opening ELF file: %d %s", error, errno_to_str(error));
        file->error = get_error_report(error);
    }
    if (!elf_cleanup_posted) {
        post_event_with_delay(elf_cleanup_event, NULL, 1000000);
        elf_cleanup_posted = 1;
    }
    free(real_name);
    file->next = files;
    return files = file;
}

ELF_File * elf_open(const char * file_name) {
    ELF_File * file = create_elf_cache(file_name);
    if (file->error == NULL) return file;
    set_error_report_errno(file->error);
    return NULL;
}

int elf_load(ELF_Section * s) {

    if (s->data != NULL) return 0;
    if (s->size == 0) return 0;

    s->relocate = 0;
    if (s->type != SHT_REL && s->type != SHT_RELA) {
        unsigned i;
        for (i = 1; i < s->file->section_cnt; i++) {
            ELF_Section * r = s->file->sections + i;
            if (r->entsize == 0 || r->size == 0) continue;
            if (r->type != SHT_REL && r->type != SHT_RELA) continue;
            if (r->info == s->index) {
                s->relocate = 1;
                break;
            }
        }
    }

#ifdef USE_MMAP
#ifdef _WIN32
    if (s->size >= 0x100000) {
        ELF_File * file = s->file;
        if (file->mmap_handle == NULL) {
            file->mmap_handle = CreateFileMapping(
                (HANDLE)_get_osfhandle(file->fd), NULL, PAGE_READONLY,
                (DWORD)(file->size >> 32), (DWORD)file->size, NULL);
            if (file->mmap_handle == NULL) {
                trace(LOG_ALWAYS, "Cannot create file mapping object: %s",
                    errno_to_str(set_win32_errno(GetLastError())));
            }
        }
        if (file->mmap_handle != NULL) {
            SYSTEM_INFO info;
            U8_T offs = s->offset;
            GetSystemInfo(&info);
            offs -= offs % info.dwAllocationGranularity;
            s->mmap_size = (size_t)(s->offset - offs + s->size);
            s->mmap_addr = MapViewOfFile(file->mmap_handle, FILE_MAP_READ,
                (DWORD)(offs >> 32), (DWORD)offs, s->mmap_size);
            if (s->mmap_addr == NULL) {
                trace(LOG_ALWAYS, "Cannot create file mapping view: %s",
                    errno_to_str(set_win32_errno(GetLastError())));
            }
            else {
                s->data = (char *)s->mmap_addr + (size_t)(s->offset - offs);
                trace(LOG_ELF, "Section %s in ELF file %s is mapped to %#lx", s->name, s->file->name, s->data);
            }
        }
    }
#else
    if (s->size >= 0x100000) {
        long page = sysconf(_SC_PAGE_SIZE);
        off_t offs = (off_t)s->offset;
        offs -= offs % page;
        s->mmap_size = (size_t)(s->offset - offs + s->size);
        s->mmap_addr = mmap(0, s->mmap_size, PROT_READ, MAP_PRIVATE, s->file->fd, offs);
        if (s->mmap_addr == MAP_FAILED) {
            s->mmap_addr = NULL;
            trace(LOG_ALWAYS, "Cannot mmap section %s in ELF file %s", s->name, s->file->name);
        }
        else {
            s->data = (char *)s->mmap_addr + (size_t)(s->offset - offs);
            trace(LOG_ELF, "Section %s in ELF file %s is mapped to %#lx", s->name, s->file->name, s->data);
        }
    }
#endif
#endif

    if (s->data == NULL) {
        ELF_File * file = s->file;
        if (lseek(file->fd, s->offset, SEEK_SET) == (off_t)-1) return -1;
        s->data = loc_alloc((size_t)s->size);
        if (read(file->fd, s->data, (size_t)s->size) < 0) {
            int err = errno;
            loc_free(s->data);
            s->data = NULL;
            set_errno(err, "Cannot read symbol file");
            return -1;
        }
        trace(LOG_ELF, "Section %s in ELF file %s is loaded", s->name, s->file->name);
    }
    return 0;
}

ELF_File * get_dwarf_file(ELF_File * file) {
    if (file != NULL && file->debug_info_file_name != NULL) {
        ELF_File * debug = elf_open(file->debug_info_file_name);
        if (debug != NULL) return debug;
    }
    return file;
}

#if ENABLE_DebugContext

ELF_File * elf_open_memory_region_file(MemoryRegion * r, int * error) {
    ELF_File * file = NULL;
    ino_t ino = r->ino;
    dev_t dev = r->dev;

    if (dev != 0) {
        if (ino == 0 && r->file_name != NULL) ino = elf_ino(r->file_name);
        if (ino != 0) file = find_open_file_by_inode(dev, ino, 0);
    }
    if (file == NULL) {
        if (r->file_name == NULL) return NULL;
        file = create_elf_cache(r->file_name);
    }
    if (file->error == NULL) {
        if (r->dev != 0 && file->dev != r->dev) return NULL;
        if (r->ino != 0 && file->ino != r->ino) return NULL;
        return file;
    }
    if (error != NULL && *error == 0) {
        int no = set_error_report_errno(file->error);
        if (get_error_code(no) != ERR_INV_FORMAT) *error = no;
    }
    return NULL;
}

static void add_region(MemoryMap * map, MemoryRegion * r) {
    if (map->region_cnt >= map->region_max) {
        map->region_max += 8;
        map->regions = (MemoryRegion *)loc_realloc(map->regions, sizeof(MemoryRegion ) * map->region_max);
    }
    map->regions[map->region_cnt++] = *r;
}

static void search_regions(MemoryMap * map, ContextAddress addr0, ContextAddress addr1, MemoryMap * res) {
    unsigned i;
    for (i = 0; i < map->region_cnt; i++) {
        MemoryRegion * r = map->regions + i;
        if (r->file_name == NULL) continue;
        if (r->addr == 0 && r->size == 0 && r->file_offs == 0 && r->sect_name == NULL) {
            ELF_File * file = elf_open_memory_region_file(r, NULL);
            if (file != NULL) {
                unsigned j;
                for (j = 0; j < file->pheader_cnt; j++) {
                    ELF_PHeader * p = file->pheaders + j;
                    if (p->type != PT_LOAD) continue;
                    if (p->address <= addr1 && p->address + p->mem_size > addr0) {
                        MemoryRegion x;
                        memset(&x, 0, sizeof(x));
                        x.addr = (ContextAddress)p->address;
                        x.size = (ContextAddress)p->mem_size;
                        x.dev = file->dev;
                        x.ino = file->ino;
                        x.file_name = file->name;
                        x.file_offs = p->offset;
                        x.flags = MM_FLAG_R | MM_FLAG_W | MM_FLAG_X;
                        add_region(res, &x);
                    }
                }
            }
        }
        else if (r->addr <= addr1 && r->size == 0 && r->sect_name != NULL) {
            ELF_File * file = elf_open_memory_region_file(r, NULL);
            if (file != NULL) {
                unsigned j;
                for (j = 0; j < file->section_cnt; j++) {
                    ELF_Section * s = file->sections + j;
                    if (s == NULL || s->name == NULL) continue;
                    if (strcmp(s->name, r->sect_name)) continue;
                    if (r->addr + s->size > addr0) {
                        MemoryRegion x;
                        memset(&x, 0, sizeof(x));
                        x.addr = r->addr;
                        x.size = (ContextAddress)s->size;
                        x.dev = file->dev;
                        x.ino = file->ino;
                        x.file_name = file->name;
                        x.sect_name = r->sect_name;
                        x.flags = r->flags;
                        if (x.flags == 0) x.flags = MM_FLAG_R | MM_FLAG_W | MM_FLAG_X;
                        add_region(res, &x);
                    }
                }
            }
        }
        else if (r->addr <= addr1 && r->addr + r->size > addr0) {
            add_region(res, r);
        }
    }
}

int elf_get_map(Context * ctx, ContextAddress addr0, ContextAddress addr1, MemoryMap * map) {
    map->region_cnt = 0;
    ctx = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
#if SERVICE_MemoryMap
    {
        MemoryMap * client_map = NULL;
        MemoryMap * target_map = NULL;
        if (memory_map_get(ctx, &client_map, &target_map) < 0) return -1;
        search_regions(client_map, addr0, addr1, map);
        search_regions(target_map, addr0, addr1, map);
    }
#else
    {
        int error = 0;
        MemoryMap target_map;
        memset(&target_map, 0, sizeof(target_map));
        if (context_get_memory_map(ctx, &target_map) < 0) error = errno;
        if (!error) search_regions(&target_map, addr0, addr1, map);
        context_clear_memory_map(&target_map);
        loc_free(target_map.regions);
        if (error) {
            errno = error;
            return -1;
        }
    }
#endif
    return 0;
}

ELF_File * elf_open_inode(Context * ctx, dev_t dev, ino_t ino, int64_t mtime) {
    unsigned i;
    int error = 0;
    ELF_File * file = find_open_file_by_inode(dev, ino, mtime);
    if (file != NULL) {
        if (file->error == NULL) return file;
        set_error_report_errno(file->error);
        return NULL;
    }
    if (elf_get_map(ctx, 0, ~(ContextAddress)0, &elf_map) < 0) return NULL;
    for (i = 0; i < elf_map.region_cnt; i++) {
        MemoryRegion * r = elf_map.regions + i;
        file = elf_open_memory_region_file(r, &error);
        if (file == NULL) continue;
        if (file->dev == dev && file->ino == ino && file->mtime == mtime) return file;
        file = get_dwarf_file(file);
        if (file->dev == dev && file->ino == ino && file->mtime == mtime) return file;
    }
    if (error == 0) error = ENOENT;
    errno = error;
    return NULL;
}

ELF_File * elf_list_first(Context * ctx, ContextAddress addr_min, ContextAddress addr_max) {
    ElfListState * state = (ElfListState *)loc_alloc_zero(sizeof(ElfListState));
    state->next = elf_list_state;
    elf_list_state = state;
    state->ctx = ctx;
    if (elf_get_map(ctx, addr_min, addr_max, &state->map) < 0) return NULL;
    if (state->map.region_cnt > 0) {
        ELF_File * f = files;
        while (f != NULL) {
            f->listed = 0;
            f = f->next;
        }
        return elf_list_next(ctx);
    }
    errno = 0;
    return NULL;
}

ELF_File * elf_list_next(Context * ctx) {
    ElfListState * state = elf_list_state;
    assert(state != NULL);
    assert(state->ctx == ctx);
    assert(state->map.region_cnt > 0);
    while (state->pos < state->map.region_cnt) {
        int error = 0;
        MemoryRegion * r = state->map.regions + state->pos++;
        ELF_File * file = elf_open_memory_region_file(r, &error);
        if (file != NULL) {
            if (file->listed) continue;
            file->listed = 1;
            return file;
        }
        if (error && r->id == NULL && get_error_code(error) != ENOENT) {
            errno = error;
            return NULL;
        }
    }
    errno = 0;
    return NULL;
}

void elf_list_done(Context * ctx) {
    ElfListState * state = elf_list_state;
    assert(state != NULL);
    assert(state->ctx == ctx);
    elf_list_state = state->next;
    free_elf_list_state(state);
}

UnitAddressRange * elf_find_unit(Context * ctx, ContextAddress addr_min, ContextAddress addr_max, ContextAddress * range_rt_addr) {
    unsigned i, j;
    UnitAddressRange * range = NULL;
    int error = 0;

    if (elf_get_map(ctx, addr_min, addr_max, &elf_map) < 0) return NULL;
    for (i = 0; range == NULL && i < elf_map.region_cnt; i++) {
        ContextAddress link_addr_min, link_addr_max;
        MemoryRegion * r = elf_map.regions + i;
        ELF_File * file = NULL;
        assert(r->addr <= addr_max);
        assert(r->addr + r->size > addr_min);
        file = elf_open_memory_region_file(r, &error);
        if (file == NULL) {
            if (error) {
                if (r->id != NULL) continue;
                if (get_error_code(error) == ENOENT) continue;
                exception(error);
            }
            continue;
        }
        if (r->sect_name == NULL) {
            for (j = 0; range == NULL && j < file->pheader_cnt; j++) {
                U8_T offs_min = 0;
                U8_T offs_max = 0;
                ELF_PHeader * p = file->pheaders + j;
                if (p->type != PT_LOAD) continue;
                if (r->flags) {
                    if ((p->flags & PF_R) && !(r->flags & MM_FLAG_R)) continue;
                    if ((p->flags & PF_W) && !(r->flags & MM_FLAG_W)) continue;
                    if ((p->flags & PF_X) && !(r->flags & MM_FLAG_X)) continue;
                }
                offs_min = addr_min - r->addr + r->file_offs;
                offs_max = addr_max - r->addr + r->file_offs;
                if (p->offset >= offs_max || p->offset + p->mem_size <= offs_min) continue;
                link_addr_min = (ContextAddress)(offs_min - p->offset + p->address);
                link_addr_max = (ContextAddress)(offs_max - p->offset + p->address);
                if (link_addr_min < p->address) link_addr_min = (ContextAddress)p->address;
                if (link_addr_max >= p->address + p->mem_size) link_addr_max = (ContextAddress)(p->address + p->mem_size);
                range = find_comp_unit_addr_range(get_dwarf_cache(file), NULL, link_addr_min, link_addr_max);
                if (range == NULL) {
                    ELF_File * debug = get_dwarf_file(file);
                    if (debug != file) {
                        if (j < debug->pheader_cnt) {
                            p = debug->pheaders + j;
                            link_addr_min = (ContextAddress)(offs_min - p->offset + p->address);
                            link_addr_max = (ContextAddress)(offs_max - p->offset + p->address);
                            if (link_addr_min < p->address) link_addr_min = (ContextAddress)p->address;
                            if (link_addr_max >= p->address + p->mem_size) link_addr_max = (ContextAddress)(p->address + p->mem_size);
                            range = find_comp_unit_addr_range(get_dwarf_cache(debug), NULL, link_addr_min, link_addr_max);
                        }
                    }
                }
                if (range != NULL && range_rt_addr != NULL) {
                    *range_rt_addr = (ContextAddress)(range->mAddr - p->address + p->offset - r->file_offs + r->addr);
                }
            }
        }
        else {
            unsigned idx;
            ELF_File * debug = get_dwarf_file(file);
            for (idx = 1; range == NULL && idx < debug->section_cnt; idx++) {
                ELF_Section * sec = debug->sections + idx;
                if (sec->name != NULL && strcmp(sec->name, r->sect_name) == 0) {
                    link_addr_min = (ContextAddress)(addr_min - r->addr + sec->addr);
                    link_addr_max = (ContextAddress)(addr_max - r->addr + sec->addr);
                    if (link_addr_min < sec->addr) link_addr_min = (ContextAddress)sec->addr;
                    if (link_addr_max >= sec->addr + sec->size) link_addr_max = (ContextAddress)(sec->addr + sec->size);
                    range = find_comp_unit_addr_range(get_dwarf_cache(debug), sec, link_addr_min, link_addr_max);
                    if (range != NULL && range_rt_addr != NULL) {
                        *range_rt_addr = (ContextAddress)(range->mAddr - sec->addr + r->addr);
                    }
                }
            }
        }
    }
    return range;
}

ContextAddress elf_run_time_address_in_region(Context * ctx, MemoryRegion * r, ELF_File * file, ELF_Section * sec, ContextAddress addr) {
    unsigned i;
    errno = 0;
    if (r->sect_name == NULL) {
        for (i = 0; i < file->pheader_cnt; i++) {
            U8_T offs;
            ELF_PHeader * p = file->pheaders + i;
            if (p->type != PT_LOAD) continue;
            if (addr < p->address || addr >= p->address + p->mem_size) continue;
            if (r->flags) {
                if ((p->flags & PF_R) && !(r->flags & MM_FLAG_R)) continue;
                if ((p->flags & PF_W) && !(r->flags & MM_FLAG_W)) continue;
                if ((p->flags & PF_X) && !(r->flags & MM_FLAG_X)) continue;
            }
            offs = addr - p->address + p->offset;
            if (offs < r->file_offs || offs >= r->file_offs + r->size) continue;
            return (ContextAddress)(offs - r->file_offs + r->addr);
        }
    }
    else if (sec != NULL) {
        if (strcmp(sec->name, r->sect_name) == 0) {
            return (ContextAddress)(addr - sec->addr + r->addr);
        }
    }
    else if (file->type == ET_EXEC || file->type == ET_DYN) {
        for (i = 1; i < file->section_cnt; i++) {
            ELF_Section * s = file->sections + i;
            if (s->addr <= addr && s->addr + s->size > addr &&
                s->name != NULL && strcmp(s->name, r->sect_name) == 0) {
                return (ContextAddress)(addr - s->addr + r->addr);
            }
        }
    }
    errno = ERR_INV_ADDRESS;
    return 0;
}

ContextAddress elf_map_to_run_time_address(Context * ctx, ELF_File * file, ELF_Section * sec, ContextAddress addr) {
    unsigned i;
    ContextAddress rt = 0;

    /* Note: 'addr' is link-time address - it cannot be used as elf_get_map() argument */
    if (elf_get_map(ctx, 0, ~(ContextAddress)0, &elf_map) < 0) return 0;
    for (i = 0; i < elf_map.region_cnt; i++) {
        MemoryRegion * r = elf_map.regions + i;
        int same_file = 0;
        if (r->dev == 0) {
            same_file = file_name_equ(file, r->file_name);
        }
        else {
           ino_t ino = r->ino;
           if (ino == 0) ino = elf_ino(r->file_name);
           same_file = file->ino == ino && file->dev == r->dev;
        }
        if (!same_file) {
            /* Check if the memory map entry has a separate debug info file */
            ELF_File * exec = NULL;
            if (!file->debug_info_file) continue;
            exec = elf_open_memory_region_file(r, NULL);
            if (exec == NULL) continue;
            if (get_dwarf_file(exec) != file) continue;
        }
        rt = elf_run_time_address_in_region(ctx, r, file, sec, addr);
        if (errno == 0) return rt;
    }
    if (file->type == ET_EXEC) {
        errno = 0;
        return addr;
    }
    errno = ERR_INV_ADDRESS;
    return 0;
}

ContextAddress elf_map_to_link_time_address(Context * ctx, ContextAddress addr, ELF_File ** file, ELF_Section ** sec) {
    unsigned i;

    if (elf_get_map(ctx, addr, addr, &elf_map) < 0) return 0;
    for (i = 0; i < elf_map.region_cnt; i++) {
        MemoryRegion * r = elf_map.regions + i;
        ELF_File * f = NULL;
        assert(r->addr <= addr);
        assert(r->addr + r->size > addr);
        f = elf_open_memory_region_file(r, NULL);
        if (f == NULL) continue;
        if (r->sect_name == NULL) {
            unsigned j;
            if (f->pheader_cnt == 0 && f->type == ET_EXEC) {
                *file = f;
                if (sec != NULL) {
                    for (j = 1; j < f->section_cnt; j++) {
                        ELF_Section * s = f->sections + j;
                        if ((s->flags & SHF_ALLOC) == 0) continue;
                        if (s->addr <= addr && s->addr + s->size > addr) {
                            *sec = s;
                            return addr;
                        }
                    }
                    *sec = NULL;
                }
                return addr;
            }
            for (j = 0; j < f->pheader_cnt; j++) {
                U8_T offs = addr - r->addr + r->file_offs;
                ELF_PHeader * p = f->pheaders + j;
                if (p->type != PT_LOAD) continue;
                if (offs < p->offset || offs >= p->offset + p->mem_size) continue;
                if (r->flags) {
                    if ((p->flags & PF_R) && !(r->flags & MM_FLAG_R)) continue;
                    if ((p->flags & PF_W) && !(r->flags & MM_FLAG_W)) continue;
                    if ((p->flags & PF_X) && !(r->flags & MM_FLAG_X)) continue;
                }
                *file = f;
                addr = (ContextAddress)(offs - p->offset + p->address);
                if (sec != NULL) {
                    for (j = 1; j < f->section_cnt; j++) {
                        ELF_Section * s = f->sections + j;
                        if ((s->flags & SHF_ALLOC) == 0) continue;
                        if (s->addr + s->size <= p->address) continue;
                        if (s->addr >= p->address + p->mem_size) continue;
                        if (s->addr <= addr && s->addr + s->size > addr) {
                            *sec = s;
                            return addr;
                        }
                    }
                    *sec = NULL;
                }
                return addr;
            }
        }
        else {
            unsigned j;
            *file = f;
            for (j = 1; j < f->section_cnt; j++) {
                ELF_Section * s = f->sections + j;
                if (strcmp(s->name, r->sect_name) == 0) {
                    if (sec != NULL) *sec = s;
                    return (ContextAddress)(addr - r->addr + s->addr);
                }
            }
        }
    }
    return 0;
}

int elf_read_memory_word(Context * ctx, ELF_File * file, ContextAddress addr, ContextAddress * word) {
    size_t size = file->elf64 ? 8 : 4;
    size_t i = 0;
    U8_T n = 0;
    U1_T buf[8];

    if (ctx->mem_access == 0) ctx = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    if (context_read_mem(ctx, addr, buf, size) < 0) return -1;
    for (i = 0; i < size; i++) {
        n = (n << 8) | buf[file->big_endian ? i : size - i - 1];
    }
    *word = (ContextAddress)n;
    return 0;
}

#endif /* ENABLE_DebugContext */


/************************ ELF symbol tables *****************************************/

unsigned calc_symbol_name_hash(const char * s) {
    unsigned h = 0;
    while (*s) {
        unsigned g;
        if (s[0] == '@' && s[1] == '@') break;
        if (s[0] == ' ' && (s[1] == '{' || s[1] == '(' || s[1] == '[')) {
            s++;
            continue;
        }
        h = (h << 4) + (unsigned char)*s++;
        g = h & 0xf0000000;
        if (g) h = (h ^ (g >> 24)) & ~g;
    }
    return h;
}

int cmp_symbol_names(const char * x, const char * y) {
    for (;;) {
        if (*x != *y) {
            if (*x == 0 && *y == '@' && y[1] == '@') return 0;
            if (*y == 0 && *x == '@' && x[1] == '@') return 0;
            if (*y == ' ' && (*x == '{' || *x == '(' || *x == '[')) {
                y++;
                continue;
            }
            if (*x == ' ' && (*y == '{' || *y == '(' || *y == '[')) {
                x++;
                continue;
            }
            break;
        }
        else if (*x == 0) {
            return 0;
        }
        else {
            x++;
            y++;
        }
    }
    if (*x < *y) return -1;
    if (*x > *y) return +1;
    return 0;
}

void unpack_elf_symbol_info(ELF_Section * sym_sec, U4_T index, ELF_SymbolInfo * info) {
    ELF_File * file = sym_sec->file;
    ELF_Section * str_sec = NULL;
    char * str_pool = NULL;
    size_t str_pool_size = 0;
    memset(info, 0, sizeof(ELF_SymbolInfo));
    if (index >= sym_sec->size / sym_sec->entsize) str_exception(ERR_INV_FORMAT, "Invalid ELF symbol index");
    if (sym_sec->link == 0 || sym_sec->link >= file->section_cnt) str_exception(ERR_INV_FORMAT, "Invalid symbol section");
    str_sec = file->sections + sym_sec->link;
    if (elf_load(sym_sec) < 0) exception(errno);
    if (elf_load(str_sec) < 0) exception(errno);
    str_pool = (char *)str_sec->data;
    str_pool_size = (size_t)str_sec->size;
    info->sym_section = sym_sec;
    info->sym_index = index;
    if (file->elf64) {
        Elf64_Sym s = *(Elf64_Sym *)((U1_T *)sym_sec->data + sym_sec->entsize * index);
        if (file->byte_swap) {
            SWAP(s.st_name);
            SWAP(s.st_shndx);
            SWAP(s.st_size);
            SWAP(s.st_value);
        }
        info->section_index = s.st_shndx;
        if (s.st_shndx > 0 && s.st_shndx < file->section_cnt) {
            info->section = file->sections + s.st_shndx;
        }
        if (s.st_name > 0) {
            if (s.st_name >= str_pool_size) str_exception(ERR_INV_FORMAT, "Invalid ELF string pool index");
            info->name = str_pool + s.st_name;
        }
        info->bind = ELF64_ST_BIND(s.st_info);
        info->type = ELF64_ST_TYPE(s.st_info);
        info->value = s.st_value;
        info->size = s.st_size;
    }
    else {
        Elf32_Sym s = *(Elf32_Sym *)((U1_T *)sym_sec->data + sym_sec->entsize * index);
        if (file->byte_swap) {
            SWAP(s.st_name);
            SWAP(s.st_shndx);
            SWAP(s.st_size);
            SWAP(s.st_value);
        }
        info->section_index = s.st_shndx;
        if (s.st_shndx > 0 && s.st_shndx < file->section_cnt) {
            info->section = file->sections + s.st_shndx;
        }
        if (s.st_name > 0) {
            if (s.st_name >= str_pool_size) str_exception(ERR_INV_FORMAT, "Invalid ELF string pool index");
            info->name = str_pool + s.st_name;
        }
        info->bind = ELF32_ST_BIND(s.st_info);
        info->type = ELF32_ST_TYPE(s.st_info);
        info->value = s.st_value;
        info->size = s.st_size;
    }

    if (file->machine == EM_ARM) {
        if (info->type == STT_FUNC || info->type == STT_ARM_TFUNC) {
            info->value = info->value & ~ (U8_T)1;
            info->type = STT_FUNC;
        }
    }
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
        if (sym.name != NULL) {
            if (sym.bind == STB_GLOBAL && sym.name[0] == '_' && sym.name[1] == '_') {
                if (strcmp(sym.name, "__GOTT_BASE__") == 0) tbl->file->vxworks_got = 1;
                else if (strcmp(sym.name, "__GOTT_INDEX__") == 0) tbl->file->vxworks_got = 1;
            }
            if (sym.section_index != SHN_UNDEF && sym.type != STT_SECTION && sym.type != STT_FILE) {
                unsigned h = calc_symbol_name_hash(sym.name) % sym_cnt;
                tbl->sym_names_next[i] = tbl->sym_names_hash[h];
                tbl->sym_names_hash[h] = i;
            }
        }
    }
}

static int section_symbol_comparator(const void * x, const void * y) {
    ELF_SecSymbol * rx = (ELF_SecSymbol *)x;
    ELF_SecSymbol * ry = (ELF_SecSymbol *)y;
    if (rx->address < ry->address) return -1;
    if (rx->address > ry->address) return +1;
    return 0;
}

static void create_symbol_addr_search_index(ELF_Section * sec) {
    ELF_File * file = sec->file;
    int elf64 = file->elf64;
    int swap = file->byte_swap;
    int rel = file->type == ET_REL;
    unsigned m = 0;

    sec->sym_addr_max = (unsigned)(sec->size / 16) + 16;
    sec->sym_addr_table = (ELF_SecSymbol *)loc_alloc(sec->sym_addr_max * sizeof(ELF_SecSymbol));

    for (m = 1; m < file->section_cnt; m++) {
        unsigned n = 1;
        ELF_Section * tbl = file->sections + m;
        if (tbl->sym_count == 0) continue;
        if (elf_load(tbl) < 0) exception(errno);
        while (n < tbl->sym_count) {
            int add = 0;
            U8_T addr = 0;
            U1_T type = 0;
            if (elf64) {
                Elf64_Sym s = ((Elf64_Sym *)tbl->data)[n];
                if (swap) SWAP(s.st_shndx);
                if (s.st_shndx == sec->index) {
                    if (swap) SWAP(s.st_value);
                    addr = s.st_value;
                    type = ELF64_ST_TYPE(s.st_info);
                    if (rel) addr += sec->addr;
                    add = 1;
                }
            }
            else {
                Elf32_Sym s = ((Elf32_Sym *)tbl->data)[n];
                if (swap) SWAP(s.st_shndx);
                if (s.st_shndx == sec->index) {
                    if (swap) SWAP(s.st_value);
                    addr = s.st_value;
                    type = ELF32_ST_TYPE(s.st_info);
                    if (rel) addr += sec->addr;
                    add = 1;
                }
            }
            if (add) {
                ELF_SecSymbol * s = NULL;
                if (file->machine == EM_ARM) {
                    if (type == STT_FUNC || type == STT_ARM_TFUNC) {
                        addr = addr & ~(U8_T)1;
                    }
                }
                if (sec->sym_addr_cnt >= sec->sym_addr_max) {
                    sec->sym_addr_max = sec->sym_addr_max * 3 / 2;
                    sec->sym_addr_table = (ELF_SecSymbol *)loc_realloc(sec->sym_addr_table, sec->sym_addr_max * sizeof(ELF_SecSymbol));
                }
                s = sec->sym_addr_table + sec->sym_addr_cnt++;
                s->address = addr;
                s->section = tbl;
                s->index = n;
            }
            n++;
        }
    }

    qsort(sec->sym_addr_table, sec->sym_addr_cnt, sizeof(ELF_SecSymbol), section_symbol_comparator);
}

void elf_find_symbol_by_address(ELF_Section * sec, ContextAddress addr, ELF_SymbolInfo * sym_info) {
    unsigned l = 0;
    unsigned h = 0;
    memset(sym_info, 0, sizeof(ELF_SymbolInfo));
    if (sec == NULL || addr < sec->addr) return;
    if (sec->sym_addr_table == NULL) create_symbol_addr_search_index(sec);
    h = sec->sym_addr_cnt;
    while (l < h) {
        unsigned k = (h + l) / 2;
        ELF_SecSymbol * info = sec->sym_addr_table + k;
        if (info->address > addr) {
            h = k;
        }
        else {
            ContextAddress next = (ContextAddress)(k < sec->sym_addr_cnt - 1 ?
                (info + 1)->address : sec->addr + sec->size);
            assert(next >= info->address);
            if (next <= addr) {
                l = k + 1;
            }
            else {
                unpack_elf_symbol_info(info->section, info->index, sym_info);
                assert(sym_info->section == sec);
                sym_info->addr_index = k;
                return;
            }
        }
    }
}

void elf_prev_symbol_by_address(ELF_SymbolInfo * sym_info) {
    if (sym_info->section != NULL && sym_info->addr_index > 0) {
        U4_T index = sym_info->addr_index - 1;
        ELF_SecSymbol * info = sym_info->section->sym_addr_table + index;
        unpack_elf_symbol_info(info->section, info->index, sym_info);
        sym_info->addr_index = index;
    }
    else {
        memset(sym_info, 0, sizeof(ELF_SymbolInfo));
    }
}

void elf_next_symbol_by_address(ELF_SymbolInfo * sym_info) {
    if (sym_info->section != NULL && sym_info->addr_index + 1 < sym_info->section->sym_addr_cnt) {
        U4_T index = sym_info->addr_index + 1;
        ELF_SecSymbol * info = sym_info->section->sym_addr_table + index;
        unpack_elf_symbol_info(info->section, info->index, sym_info);
        sym_info->addr_index = index;
    }
    else {
        memset(sym_info, 0, sizeof(ELF_SymbolInfo));
    }
}

int elf_find_got_entry(ELF_File * file, const char * name, ContextAddress * addr) {
    Trap trap;
    unsigned idx;
    if (!set_trap(&trap)) return -1;
    for (idx = 1; idx < file->section_cnt; idx++) {
        U4_T i = 0;
        U4_T n = 0;
        ELF_Section * sec = file->sections + idx;
        if (sec->type != SHT_RELA) continue;
        if (sec->link == 0 || sec->link >= file->section_cnt) continue;
        if ((file->sections + sec->link)->type != SHT_DYNSYM) continue;
        if (elf_load(sec) < 0) exception(errno);
        n = (U4_T)(sec->size / sec->entsize);
        while (i < n) {
            U4_T sym_index = 0;
            U8_T got_addr = 0;
            ELF_SymbolInfo sym_info;
            if (!file->elf64) {
                Elf32_Rela bf = *(Elf32_Rela *)((U1_T *)sec->data + i * sec->entsize);
                if (file->byte_swap) {
                    SWAP(bf.r_offset);
                    SWAP(bf.r_info);
                }
                sym_index = ELF32_R_SYM(bf.r_info);
                got_addr = bf.r_offset;
            }
            else {
                Elf64_Rela bf = *(Elf64_Rela *)((U1_T *)sec->data + i * sec->entsize);
                if (file->byte_swap) {
                    SWAP(bf.r_offset);
                    SWAP(bf.r_info);
                }
                sym_index = ELF64_R_SYM(bf.r_info);
                got_addr = bf.r_offset;
            }
            unpack_elf_symbol_info(file->sections + sec->link, sym_index, &sym_info);
            if (sym_info.name != NULL && strcmp(sym_info.name, name) == 0) {
                *addr = (ContextAddress)got_addr;
                clear_trap(&trap);
                return 0;
            }
            i++;
        }
    }
    clear_trap(&trap);
    *addr = 0;
    return 0;
}

int elf_find_plt_dynsym(ELF_Section * plt, unsigned entry, ELF_SymbolInfo * sym_info, ContextAddress * offs) {
    Trap trap;
    unsigned idx;
    ELF_File * file = plt->file;

    if (!set_trap(&trap)) return -1;
    for (idx = 1; idx < file->section_cnt; idx++) {
        U4_T sym_index = 0;
        U8_T sym_offset = 0;
        ELF_Section * sec = file->sections + idx;
        if (sec->name == NULL || sec->entsize == 0) continue;
        if (sec->type != SHT_REL && sec->type != SHT_RELA) continue;
        if (sec->link == 0 || sec->link >= file->section_cnt) continue;
        if ((file->sections + sec->link)->type != SHT_DYNSYM) continue;
        if (strcmp(sec->name, ".rel.plt") != 0 && strcmp(sec->name, ".rela.plt") != 0) continue;
        if (entry >= sec->size / sec->entsize) break;
        if (elf_load(sec) < 0) exception(errno);
        if (sec->type == SHT_REL) {
            if (!file->elf64) {
                Elf32_Rel bf = *(Elf32_Rel *)((U1_T *)sec->data + entry * sec->entsize);
                if (file->byte_swap) {
                    SWAP(bf.r_info);
                }
                sym_index = ELF32_R_SYM(bf.r_info);
            }
            else {
                Elf64_Rel bf = *(Elf64_Rel *)((U1_T *)sec->data + entry * sec->entsize);
                if (file->byte_swap) {
                    SWAP(bf.r_info);
                }
                sym_index = ELF64_R_SYM(bf.r_info);
            }
        }
        else {
            if (!file->elf64) {
                Elf32_Rela bf = *(Elf32_Rela *)((U1_T *)sec->data + entry * sec->entsize);
                if (file->byte_swap) {
                    SWAP(bf.r_addend);
                    SWAP(bf.r_info);
                }
                sym_index = ELF32_R_SYM(bf.r_info);
                sym_offset = bf.r_addend;
            }
            else {
                Elf64_Rela bf = *(Elf64_Rela *)((U1_T *)sec->data + entry * sec->entsize);
                if (file->byte_swap) {
                    SWAP(bf.r_addend);
                    SWAP(bf.r_info);
                }
                sym_index = ELF64_R_SYM(bf.r_info);
                sym_offset = bf.r_addend;
            }
        }
        *offs = (ContextAddress)sym_offset;
        unpack_elf_symbol_info(file->sections + sec->link, sym_index, sym_info);
        clear_trap(&trap);
        return 0;
    }
    clear_trap(&trap);
    memset(sym_info, 0, sizeof(ELF_SymbolInfo));
    return 0;
}

int elf_get_plt_entry_size(ELF_File * file, unsigned * first_size, unsigned * entry_size) {
    switch (file->machine) {
    case EM_386:
    case EM_X86_64:
        *first_size = 16;
        *entry_size = 16;
        return 0;
    case EM_PPC:
        if (file->vxworks_got) {
            *first_size = 32;
            *entry_size = 32;
            return 0;
        }
        *first_size = 72;
        *entry_size = 12;
        return 0;
    case EM_ARM:
        *first_size = 20;
        *entry_size = 12;
        return 0;
    case EM_MIPS:
        if (file->vxworks_got) {
            *first_size = 24;
            *entry_size = 8;
            return 0;
        }
        *first_size = 32;
        *entry_size = 16;
        return 0;
    }
    errno = set_errno(ERR_OTHER, "Unknown PLT entry size");
    return -1;
}

void ini_elf(void) {
}

#endif /* ENABLE_ELF */
