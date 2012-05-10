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
 * This module implements Breakpoints service.
 * The service maintains a list of breakpoints.
 * Each breakpoint consists of one or more conditions that determine
 * when a program's execution should be interrupted.
 */

#include <tcf/config.h>

#if SERVICE_Breakpoints

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <tcf/framework/channel.h>
#include <tcf/framework/protocol.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/cache.h>
#include <tcf/framework/json.h>
#include <tcf/framework/link.h>
#include <tcf/services/symbols.h>
#include <tcf/services/runctrl.h>
#include <tcf/services/contextquery.h>
#include <tcf/services/breakpoints.h>
#include <tcf/services/expressions.h>
#include <tcf/services/linenumbers.h>
#include <tcf/services/stacktrace.h>
#include <tcf/services/memorymap.h>
#include <tcf/services/pathmap.h>

typedef struct BreakpointRef BreakpointRef;
typedef struct InstructionRef InstructionRef;
typedef struct BreakInstruction BreakInstruction;
typedef struct EvaluationArgs EvaluationArgs;
typedef struct EvaluationRequest EvaluationRequest;
typedef struct ConditionEvaluationRequest ConditionEvaluationRequest;
typedef struct ContextExtensionBP ContextExtensionBP;
typedef struct BreakpointHitCount BreakpointHitCount;

struct BreakpointRef {
    LINK link_inp;
    LINK link_bp;
    Channel * channel; /* NULL means API client */
    BreakpointInfo * bp;
};

struct BreakpointInfo {
    Context * ctx; /* NULL means all contexts */
    LINK link_all;
    LINK link_id;
    LINK link_clients;
    char id[256];
    int enabled;
    int client_cnt;
    int instruction_cnt;
    ErrorReport * error;
    char * type;
    char * location;
    char * condition;
    char * context_query;
    char ** context_ids;
    char ** context_names;
    char ** stop_group;
    char * file;
    char * client_data;
    int temporary;
    int access_mode;
    int access_size;
    int line;
    int column;
    unsigned ignore_count;
    BreakpointAttribute * attrs;

    EventPointCallBack * event_callback;
    void * event_callback_args;

    int attrs_changed;
    int status_changed;
    LINK link_hit_count;
};

struct BreakpointHitCount {
    LINK link_bp;
    LINK link_ctx;
    Context * ctx;
    unsigned count;
};

struct InstructionRef {
    BreakpointInfo * bp;
    Context * ctx; /* "breakpoint" group context, see CONTEXT_GROUP_BREAKPOINT */
    ContextAddress addr;
    int cnt;
};

struct BreakInstruction {
    LINK link_all;
    LINK link_adr;
    ContextBreakpoint cb; /* cb.ctx is "canonical" context, see context_get_canonical_addr() */
    char saved_code[16];
    size_t saved_size;
    ErrorReport * planting_error;
    ErrorReport * address_error;
    int stepping_over_bp;
    InstructionRef * refs;
    int ref_size;
    int ref_cnt;
    uint8_t no_addr;
    uint8_t virtual_addr;
    uint8_t valid;
    uint8_t planted;
    BreakInstruction * ph_addr_bi;
};

struct EvaluationArgs {
    int in_cache;
    BreakpointInfo * bp;
    Context * ctx;
    int index;
};

struct ConditionEvaluationRequest {
    Context * ctx;
    BreakpointInfo * bp;
    int condition_ok;
    int triggered;
};

struct EvaluationRequest {
    Context * ctx; /* Must be breakpoints group context */
    BreakpointInfo * bp; /* NULL means all breakpoints */
    LINK link_posted;
    LINK link_active;
    int location;
    int bp_cnt;
    int bp_max;
    ConditionEvaluationRequest * bp_arr;
};

struct ContextExtensionBP {
    int                 step_over_bp_cnt;
    BreakInstruction *  stepping_over_bp;   /* if not NULL, the context is stepping over a breakpoint instruction */
    char **             bp_ids;             /* if stopped by breakpoint, contains NULL-terminated list of breakpoint IDs */
    EvaluationRequest * req;
    Context *           bp_grp;
    int                 empty_bp_grp;
    LINK                link_hit_count;
};

static const char * BREAKPOINTS = "Breakpoints";

static size_t context_extension_offset = 0;

typedef struct Listener {
    BreakpointsEventListener * listener;
    void * args;
} Listener;

static Listener * listeners = NULL;
static unsigned listener_cnt = 0;
static unsigned listener_max = 0;

#define EXT(ctx) ((ContextExtensionBP *)((char *)(ctx) + context_extension_offset))

#define is_disabled(bp) (bp->enabled == 0 || bp->client_cnt == 0)

#define ADDR2INSTR_HASH_SIZE (32 * MEM_USAGE_FACTOR - 1)
#define addr2instr_hash(ctx, addr) ((unsigned)((uintptr_t)(ctx) + (uintptr_t)(addr) + ((uintptr_t)(addr) >> 8)) % ADDR2INSTR_HASH_SIZE)

#define link_all2bi(A)  ((BreakInstruction *)((char *)(A) - offsetof(BreakInstruction, link_all)))
#define link_adr2bi(A)  ((BreakInstruction *)((char *)(A) - offsetof(BreakInstruction, link_adr)))

#define ID2BP_HASH_SIZE (32 * MEM_USAGE_FACTOR - 1)

#define link_all2bp(A)  ((BreakpointInfo *)((char *)(A) - offsetof(BreakpointInfo, link_all)))
#define link_id2bp(A)   ((BreakpointInfo *)((char *)(A) - offsetof(BreakpointInfo, link_id)))

#define INP2BR_HASH_SIZE (4 * MEM_USAGE_FACTOR - 1)

#define link_inp2br(A)  ((BreakpointRef *)((char *)(A) - offsetof(BreakpointRef, link_inp)))
#define link_bp2br(A)   ((BreakpointRef *)((char *)(A) - offsetof(BreakpointRef, link_bp)))

#define link_posted2erl(A)  ((EvaluationRequest *)((char *)(A) - offsetof(EvaluationRequest, link_posted)))
#define link_active2erl(A)  ((EvaluationRequest *)((char *)(A) - offsetof(EvaluationRequest, link_active)))
#define link_bcg2chnl(A) ((Channel *)((char *)(A) - offsetof(Channel, bclink)))

#define link_bp2hcnt(A)  ((BreakpointHitCount *)((char *)(A) - offsetof(BreakpointHitCount, link_bp)))
#define link_ctx2hcnt(A)  ((BreakpointHitCount *)((char *)(A) - offsetof(BreakpointHitCount, link_ctx)))

static LINK breakpoints = TCF_LIST_INIT(breakpoints);
static LINK id2bp[ID2BP_HASH_SIZE];

static LINK instructions = TCF_LIST_INIT(instructions);
static LINK addr2instr[ADDR2INSTR_HASH_SIZE];

static LINK inp2br[INP2BR_HASH_SIZE];

static LINK evaluations_posted = TCF_LIST_INIT(evaluations_posted);
static LINK evaluations_active = TCF_LIST_INIT(evaluations_active);
static uintptr_t generation_posted = 0;
static uintptr_t generation_active = 0;
static uintptr_t generation_done = 0;
static int planting_instruction = 0;
static int cache_enter_cnt = 0;

static ErrorReport * bp_location_error = NULL;

static TCFBroadcastGroup * broadcast_group = NULL;

static unsigned id2bp_hash(char * id) {
    unsigned hash = 0;
    while (*id) hash = (hash >> 16) + hash + (unsigned char)*id++;
    return hash % ID2BP_HASH_SIZE;
}

static unsigned get_bp_access_types(BreakpointInfo * bp, int virtual_addr) {
    char * type = bp->type;
    unsigned access_types = bp->access_mode;
    if (access_types == 0 && (bp->file != NULL || bp->location != NULL)) access_types |= CTX_BP_ACCESS_INSTRUCTION;
    if (type != NULL && strcmp(type, "Software") == 0) access_types |= CTX_BP_ACCESS_SOFTWARE;
    if (virtual_addr) access_types |= CTX_BP_ACCESS_VIRTUAL;
    return access_types;
}

static unsigned get_bi_access_types(BreakInstruction * bi) {
    int i;
    unsigned access_types = 0;
    if (bi->no_addr) access_types |= CTX_BP_ACCESS_NO_ADDRESS;
    for (i = 0; i < bi->ref_cnt; i++) {
        if (bi->refs[i].cnt) access_types |= get_bp_access_types(bi->refs[i].bp, bi->virtual_addr);
    }
    return access_types;
}

static int is_software_break_instruction(BreakInstruction * bi) {
    unsigned mask = ~(unsigned)(CTX_BP_ACCESS_VIRTUAL | CTX_BP_ACCESS_SOFTWARE);
    return (bi->cb.access_types & mask) == CTX_BP_ACCESS_INSTRUCTION && bi->cb.length == 1 && !bi->virtual_addr;
}

static void plant_instruction(BreakInstruction * bi) {
    int error = 0;
    size_t saved_size = bi->saved_size;
    ErrorReport * rp = NULL;

    assert(!bi->stepping_over_bp);
    assert(!bi->planted);
    assert(!bi->cb.ctx->exited);
    assert(!bi->cb.ctx->exiting);
    assert(bi->valid || bi->virtual_addr);
    if (bi->address_error != NULL) return;
    assert(is_all_stopped(bi->cb.ctx));

    bi->saved_size = 0;
    bi->cb.access_types = get_bi_access_types(bi);

    if (context_plant_breakpoint(&bi->cb) < 0) error = errno;

    if (error && is_software_break_instruction(bi) && get_error_code(error) == ERR_UNSUPPORTED) {
        uint8_t * break_inst = get_break_instruction(bi->cb.ctx, &bi->saved_size);
        assert(sizeof(bi->saved_code) >= bi->saved_size);
        assert(!bi->virtual_addr);
        error = 0;
        planting_instruction = 1;
        if (context_read_mem(bi->cb.ctx, bi->cb.address, bi->saved_code, bi->saved_size) < 0) {
            error = errno;
        }
        else if (context_write_mem(bi->cb.ctx, bi->cb.address, break_inst, bi->saved_size) < 0) {
            error = errno;
        }
        planting_instruction = 0;
    }
    else if (error == ERR_UNSUPPORTED) {
        error = set_errno(ERR_OTHER, "Unsupported set of breakpoint attributes");
    }

    rp = get_error_report(error);
    if (saved_size != bi->saved_size || !compare_error_reports(bi->planting_error, rp)) {
        int i;
        release_error_report(bi->planting_error);
        bi->planting_error = rp;
        for (i = 0; i < bi->ref_cnt; i++) {
            bi->refs[i].bp->status_changed = 1;
        }
    }
    else {
        release_error_report(rp);
    }
    bi->planted = bi->planting_error == NULL;
}

static void remove_instruction(BreakInstruction * bi) {
    assert(bi->planted);
    assert(bi->planting_error == NULL);
    assert(bi->address_error == NULL);
    assert(is_all_stopped(bi->cb.ctx));
    if (bi->saved_size) {
        if (!bi->cb.ctx->exited) {
            planting_instruction = 1;
            if (context_write_mem(bi->cb.ctx, bi->cb.address, bi->saved_code, bi->saved_size) < 0) {
                bi->planting_error = get_error_report(errno);
            }
            planting_instruction = 0;
        }
    }
    else if (context_unplant_breakpoint(&bi->cb) < 0) {
        bi->planting_error = get_error_report(errno);
    }
    bi->planted = 0;
}

#ifndef NDEBUG
static int is_canonical_addr(Context * ctx, ContextAddress address) {
    Context * mem = NULL;
    ContextAddress mem_addr = 0;
    if (context_get_canonical_addr(ctx, address, &mem, &mem_addr, NULL, NULL) < 0) return 0;
    return mem == ctx && address == mem_addr;
}
#endif

static BreakInstruction * find_instruction(Context * ctx, int virtual_addr,
        ContextAddress address, unsigned access_types, ContextAddress access_size) {
    int hash = addr2instr_hash(ctx, address);
    LINK * l = addr2instr[hash].next;
    if (address == 0) return NULL;
    assert(virtual_addr || is_canonical_addr(ctx, address));
    while (l != addr2instr + hash) {
        BreakInstruction * bi = link_adr2bi(l);
        if (bi->cb.ctx == ctx &&
            bi->cb.address == address &&
            bi->virtual_addr == virtual_addr &&
            bi->no_addr == 0)
        {
            if (bi->cb.access_types == access_types && bi->cb.length == access_size) return bi;
            if (!virtual_addr && access_types == CTX_BP_ACCESS_INSTRUCTION && access_size == 1 &&
                is_software_break_instruction(bi)) return bi;
        }
        l = l->next;
    }
    return NULL;
}

static BreakInstruction * add_instruction(Context * ctx, int virtual_addr,
        ContextAddress address, unsigned access_types, ContextAddress access_size) {
    int hash = addr2instr_hash(ctx, address);
    BreakInstruction * bi = (BreakInstruction *)loc_alloc_zero(sizeof(BreakInstruction));
    assert(find_instruction(ctx, virtual_addr, address, access_types, access_size) == NULL);
    list_add_last(&bi->link_all, &instructions);
    list_add_last(&bi->link_adr, addr2instr + hash);
    context_lock(ctx);
    bi->cb.ctx = ctx;
    bi->cb.address = address;
    bi->cb.length = access_size;
    bi->cb.access_types = access_types;
    bi->virtual_addr = (uint8_t)virtual_addr;
    return bi;
}

static void clear_instruction_refs(Context * ctx, BreakpointInfo * bp) {
    LINK * l = instructions.next;
    while (l != &instructions) {
        int i;
        BreakInstruction * bi = link_all2bi(l);
        for (i = 0; i < bi->ref_cnt; i++) {
            InstructionRef * ref = bi->refs + i;
            if (ref->ctx != ctx) continue;
            if (bp != NULL && ref->bp != bp) continue;
            ref->cnt = 0;
            bi->valid = 0;
        }
        l = l->next;
    }
}

static void free_instruction(BreakInstruction * bi) {
    assert(bi->planted == 0);
    assert(bi->ref_cnt == 0);
    list_remove(&bi->link_all);
    list_remove(&bi->link_adr);
    context_unlock(bi->cb.ctx);
    release_error_report(bi->address_error);
    release_error_report(bi->planting_error);
    loc_free(bi->refs);
    loc_free(bi);
}

static void flush_instructions(void) {
    LINK * l = instructions.next;
    while (l != &instructions) {
        int i = 0;
        int replant = 0;
        BreakInstruction * bi = link_all2bi(l);
        l = l->next;
        if (bi->valid) continue;
        while (i < bi->ref_cnt) {
            if (bi->refs[i].cnt == 0 || bi->refs[i].ctx->exiting) {
                bi->refs[i].bp->instruction_cnt--;
                bi->refs[i].bp->status_changed = 1;
                context_unlock(bi->refs[i].ctx);
                memmove(bi->refs + i, bi->refs + i + 1, sizeof(InstructionRef) * (bi->ref_cnt - i - 1));
                bi->ref_cnt--;
                replant = 1;
            }
            else {
                if (bi->refs[i].bp->attrs_changed) replant = 1;
                i++;
            }
        }
        bi->valid = 1;
        if (!bi->stepping_over_bp) {
            if (bi->ref_cnt == 0) {
                if (bi->planted) remove_instruction(bi);
                free_instruction(bi);
            }
            else if (!bi->planted) {
                plant_instruction(bi);
            }
            else if (replant) {
                remove_instruction(bi);
                plant_instruction(bi);
            }
        }
    }
}

static unsigned get_bp_hit_count(BreakpointInfo * bp, Context * ctx) {
    unsigned count = 0;
    LINK * l = bp->link_hit_count.next;
    while (l != &bp->link_hit_count) {
        BreakpointHitCount * c = link_bp2hcnt(l);
        if (c->ctx == ctx) count += c->count;
        l = l->next;
    }
    return count;
}

static unsigned inc_bp_hit_count(BreakpointInfo * bp, Context * ctx) {
    unsigned count = 0;
    LINK * l = bp->link_hit_count.next;
    while (l != &bp->link_hit_count) {
        BreakpointHitCount * c = link_bp2hcnt(l);
        if (c->ctx == ctx) {
            c->count++;
            count += c->count;
            break;
        }
        l = l->next;
    }
    if (count == 0) {
        BreakpointHitCount * c = (BreakpointHitCount *)loc_alloc_zero(sizeof(BreakpointHitCount));
        list_add_first(&c->link_bp, &bp->link_hit_count);
        list_add_first(&c->link_ctx, &(EXT(ctx))->link_hit_count);
        c->count = count = 1;
        c->ctx = ctx;
    }
    bp->status_changed = 1;
    return count;
}

static void reset_bp_hit_count(BreakpointInfo * bp) {
    LINK * l = bp->link_hit_count.next;
    while (l != &bp->link_hit_count) {
        BreakpointHitCount * c = link_bp2hcnt(l);
        l = l->next;
        list_remove(&c->link_bp);
        list_remove(&c->link_ctx);
        loc_free(c);
        bp->status_changed = 1;
    }
}

void clone_breakpoints_on_process_fork(Context * parent, Context * child) {
    Context * mem = context_get_group(parent, CONTEXT_GROUP_PROCESS);
    LINK * l = instructions.next;
    while (l != &instructions) {
        int i;
        BreakInstruction * ci = NULL;
        BreakInstruction * bi = link_all2bi(l);
        l = l->next;
        if (!bi->planted) continue;
        if (!bi->saved_size) continue;
        if (bi->cb.ctx != mem) continue;
        ci = add_instruction(child, bi->virtual_addr, bi->cb.address, bi->cb.access_types, bi->cb.length);
        memcpy(ci->saved_code, bi->saved_code, bi->saved_size);
        ci->saved_size = bi->saved_size;
        ci->ref_size = bi->ref_size;
        ci->ref_cnt = bi->ref_cnt;
        ci->refs = (InstructionRef *)loc_alloc_zero(sizeof(InstructionRef) * ci->ref_size);
        for (i = 0; i < bi->ref_cnt; i++) {
            BreakpointInfo * bp = bi->refs[i].bp;
            ci->refs[i] = bi->refs[i];
            ci->refs[i].ctx = child;
            context_lock(child);
            bp->instruction_cnt++;
            bp->status_changed = 1;
        }
        ci->valid = 1;
        ci->planted = 1;
    }
}

void unplant_breakpoints(Context * ctx) {
    LINK * l = instructions.next;
    while (l != &instructions) {
        int i;
        BreakInstruction * bi = link_all2bi(l);
        l = l->next;
        if (bi->cb.ctx != ctx) continue;
        if (bi->planted) remove_instruction(bi);
        for (i = 0; i < bi->ref_cnt; i++) {
            BreakpointInfo * bp = bi->refs[i].bp;
            assert(bp->instruction_cnt > 0);
            bp->instruction_cnt--;
            bp->status_changed = 1;
            context_unlock(bi->refs[i].ctx);
        }
        bi->ref_cnt = 0;
        free_instruction(bi);
    }
}

int check_breakpoints_on_memory_read(Context * ctx, ContextAddress address, void * p, size_t size) {
    if (!planting_instruction) {
        while (size > 0) {
            size_t sz = size;
            uint8_t * buf = (uint8_t *)p;
            LINK * l = instructions.next;
            Context * mem = NULL;
            ContextAddress mem_addr = 0;
            ContextAddress mem_base = 0;
            ContextAddress mem_size = 0;
            if (context_get_canonical_addr(ctx, address, &mem, &mem_addr, &mem_base, &mem_size) < 0) return -1;
            if ((size_t)(mem_base + mem_size - mem_addr) < sz) sz = (size_t)(mem_base + mem_size - mem_addr);
            while (l != &instructions) {
                BreakInstruction * bi = link_all2bi(l);
                size_t i;
                l = l->next;
                if (!bi->planted) continue;
                if (!bi->saved_size) continue;
                if (bi->cb.ctx != mem) continue;
                if (bi->cb.address + bi->saved_size <= mem_addr) continue;
                if (bi->cb.address >= mem_addr + sz) continue;
                for (i = 0; i < bi->saved_size; i++) {
                    if (bi->cb.address + i < mem_addr) continue;
                    if (bi->cb.address + i >= mem_addr + sz) continue;
                    buf[bi->cb.address + i - mem_addr] = bi->saved_code[i];
                }
            }
            p = (uint8_t *)p + sz;
            address += sz;
            size -= sz;
        }
    }
    return 0;
}

int check_breakpoints_on_memory_write(Context * ctx, ContextAddress address, void * p, size_t size) {
    if (!planting_instruction) {
        while (size > 0) {
            size_t sz = size;
            uint8_t * buf = (uint8_t *)p;
            LINK * l = instructions.next;
            Context * mem = NULL;
            ContextAddress mem_addr = 0;
            ContextAddress mem_base = 0;
            ContextAddress mem_size = 0;
            if (context_get_canonical_addr(ctx, address, &mem, &mem_addr, &mem_base, &mem_size) < 0) return -1;
            if ((size_t)(mem_base + mem_size - mem_addr) < sz) sz = (size_t)(mem_base + mem_size - mem_addr);
            while (l != &instructions) {
                BreakInstruction * bi = link_all2bi(l);
                l = l->next;
                if (!bi->planted) continue;
                if (!bi->saved_size) continue;
                if (bi->cb.ctx != mem) continue;
                if (bi->cb.address + bi->saved_size <= mem_addr) continue;
                if (bi->cb.address >= mem_addr + sz) continue;
                {
                    size_t i;
                    uint8_t * break_inst = get_break_instruction(bi->cb.ctx, &i);
                    assert(i == bi->saved_size);
                    for (i = 0; i < bi->saved_size; i++) {
                        if (bi->cb.address + i < mem_addr) continue;
                        if (bi->cb.address + i >= mem_addr + sz) continue;
                        bi->saved_code[i] = buf[bi->cb.address + i - mem_addr];
                        buf[bi->cb.address + i - mem_addr] = break_inst[i];
                    }
                }
            }
            p = (uint8_t *)p + sz;
            address += sz;
            size -= sz;
        }
    }
    return 0;
}

static void write_breakpoint_status(OutputStream * out, BreakpointInfo * bp) {
    assert(*bp->id);
    write_stream(out, '{');

    if (bp->instruction_cnt) {
        int cnt = 0;
        LINK * l = instructions.next;
        json_write_string(out, "Instances");
        write_stream(out, ':');
        write_stream(out, '[');
        while (l != &instructions) {
            int i = 0;
            BreakInstruction * bi = link_all2bi(l);
            l = l->next;
            if (bi->ph_addr_bi != NULL) continue;
            for (i = 0; i < bi->ref_cnt; i++) {
                if (bi->refs[i].bp != bp) continue;
                if (cnt > 0) write_stream(out, ',');
                write_stream(out, '{');
                json_write_string(out, "LocationContext");
                write_stream(out, ':');
                json_write_string(out, bi->refs[i].ctx->id);
                if (bi->address_error != NULL) {
                    write_stream(out, ',');
                    json_write_string(out, "Error");
                    write_stream(out, ':');
                    json_write_string(out, errno_to_str(set_error_report_errno(bi->address_error)));
                }
                else {
                    write_stream(out, ',');
                    json_write_string(out, "HitCount");
                    write_stream(out, ':');
                    json_write_ulong(out, get_bp_hit_count(bp, bi->refs[i].ctx));
                    if (!bi->no_addr) {
                        write_stream(out, ',');
                        json_write_string(out, "Address");
                        write_stream(out, ':');
                        json_write_uint64(out, bi->refs[i].addr);
                    }
                    if (bi->cb.length > 0) {
                        write_stream(out, ',');
                        json_write_string(out, "Size");
                        write_stream(out, ':');
                        json_write_uint64(out, bi->cb.length);
                    }
                    if (bi->planting_error != NULL) {
                        write_stream(out, ',');
                        json_write_string(out, "Error");
                        write_stream(out, ':');
                        json_write_string(out, errno_to_str(set_error_report_errno(bi->planting_error)));
                    }
                    else if (bi->planted) {
                        write_stream(out, ',');
                        json_write_string(out, "BreakpointType");
                        write_stream(out, ':');
                        json_write_string(out, bi->saved_size ? "Software" : "Hardware");
#if ENABLE_ExtendedBreakpointStatus
                        if (bi->saved_size == 0) {
                            /* Back-end context breakpoint status */
                            int cnt = 0;
                            const char ** names = NULL;
                            const char ** values = NULL;
                            if (context_get_breakpoint_status(&bi->cb, &names, &values, &cnt) == 0) {
                                while (cnt > 0) {
                                    if (*values != NULL) {
                                        write_stream(out, ',');
                                        json_write_string(out, *names);
                                        write_stream(out, ':');
                                        write_string(out, *values);
                                    }
                                    names++;
                                    values++;
                                    cnt--;
                                }
                            }
                        }
#endif
                    }
                }
                write_stream(out, '}');
                cnt++;
            }
        }
        write_stream(out, ']');
        assert(cnt > 0);
    }
    else if (bp->error) {
        json_write_string(out, "Error");
        write_stream(out, ':');
        json_write_string(out, errno_to_str(set_error_report_errno(bp->error)));
    }

    write_stream(out, '}');
}

static void send_event_breakpoint_status(Channel * channel, BreakpointInfo * bp) {
    OutputStream * out = channel ? &channel->out : &broadcast_group->out;
    unsigned i;

    write_stringz(out, "E");
    write_stringz(out, BREAKPOINTS);
    write_stringz(out, "status");

    json_write_string(out, bp->id);
    write_stream(out, 0);
    write_breakpoint_status(out, bp);
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);
    if (channel) return;

    for (i = 0; i < listener_cnt; i++) {
        Listener * l = listeners + i;
        if (l->listener->breakpoint_status_changed == NULL) continue;
        l->listener->breakpoint_status_changed(bp, l->args);
    }
}

static BreakInstruction * link_breakpoint_instruction(
        BreakpointInfo * bp, Context * ctx,
        ContextAddress ctx_addr, ContextAddress size,
        Context * mem, int virtual_addr, ContextAddress mem_addr,
        ErrorReport * address_error) {

    BreakInstruction * bi = NULL;
    InstructionRef * ref = NULL;

    if (mem == NULL) {
        /* Breakpoint does not have an address, e.g. breakpoint on a signal or I/O event */
        int hash = addr2instr_hash(ctx, bp);
        LINK * l = addr2instr[hash].next;
        assert(ctx_addr == 0);
        assert(mem_addr == 0);
        assert(virtual_addr == 0);
        while (l != addr2instr + hash) {
            BreakInstruction * i = link_adr2bi(l);
            if (i->cb.ctx == ctx && i->no_addr && i->ref_cnt == 1 &&
                    i->refs[0].ctx == ctx && i->refs[0].bp == bp &&
                    compare_error_reports(address_error, i->address_error)) {
                release_error_report(address_error);
                i->refs[0].cnt++;
                return i;
            }
            l = l->next;
        }
        bi = (BreakInstruction *)loc_alloc_zero(sizeof(BreakInstruction));
        list_add_last(&bi->link_all, &instructions);
        list_add_last(&bi->link_adr, addr2instr + hash);
        context_lock(ctx);
        bi->cb.ctx = ctx;
        bi->no_addr = 1;
        bi->address_error = address_error;
    }
    else {
        unsigned access_types = get_bp_access_types(bp, virtual_addr);
        bi = find_instruction(mem, virtual_addr, mem_addr, access_types, size);
        if (bi == NULL) {
            bi = add_instruction(mem, virtual_addr, mem_addr, access_types, size);
        }
        else {
            int i = 0;
            bi->ph_addr_bi = NULL;
            while (i < bi->ref_cnt) {
                ref = bi->refs + i;
                if (ref->bp == bp && ref->ctx == ctx) {
                    assert(!bi->valid);
                    ref->addr = ctx_addr;
                    ref->cnt++;
                    return bi;
                }
                i++;
            }
        }
    }
    if (bi->ref_cnt >= bi->ref_size) {
        bi->ref_size = bi->ref_size == 0 ? 8 : bi->ref_size * 2;
        bi->refs = (InstructionRef *)loc_realloc(bi->refs, sizeof(InstructionRef) * bi->ref_size);
    }
    ref = bi->refs + bi->ref_cnt++;
    context_lock(ctx);
    memset(ref, 0, sizeof(InstructionRef));
    ref->bp = bp;
    ref->ctx = ctx;
    ref->addr = ctx_addr;
    ref->cnt = 1;
    bi->valid = 0;
    bp->instruction_cnt++;
    bp->status_changed = 1;
    return bi;
}

static void address_expression_error(Context * ctx, BreakpointInfo * bp, int error) {
    ErrorReport * rp = NULL;
    if (get_error_code(errno) == ERR_CACHE_MISS) return;
    assert(error != 0);
    assert(bp->instruction_cnt == 0 || bp->error == NULL);
    rp = get_error_report(error);
    assert(rp != NULL);
    link_breakpoint_instruction(bp, ctx, 0, 0, NULL, 0, 0, rp);
}

static void plant_breakpoint(Context * ctx, BreakpointInfo * bp, ContextAddress addr, ContextAddress size) {
    Context * mem = NULL;
    ContextAddress mem_addr = 0;
    BreakInstruction * v_bi = NULL;
    BreakInstruction * p_bi = NULL;

    if (context_get_supported_bp_access_types(ctx) & CTX_BP_ACCESS_VIRTUAL) {
        v_bi = link_breakpoint_instruction(bp, ctx, addr, size, ctx, 1, addr, NULL);
        if (!v_bi->planted) plant_instruction(v_bi);
        if (v_bi->planted) return;
    }

    if (context_get_canonical_addr(ctx, addr, &mem, &mem_addr, NULL, NULL) < 0) {
        address_expression_error(ctx, bp, errno);
    }
    else {
        p_bi = link_breakpoint_instruction(bp, ctx, addr, size, mem, 0, mem_addr, NULL);
        if (v_bi != NULL) v_bi->ph_addr_bi = p_bi;
    }
}

static void event_replant_breakpoints(void * arg);

static EvaluationRequest * create_evaluation_request(Context * ctx) {
    EvaluationRequest * req = EXT(ctx)->req;
    if (req == NULL) {
        req = (EvaluationRequest *)loc_alloc_zero(sizeof(EvaluationRequest));
        req->ctx = ctx;
        list_init(&req->link_posted);
        list_init(&req->link_active);
        EXT(ctx)->req = req;
    }
    assert(req->ctx == ctx);
    return req;
}

static ConditionEvaluationRequest * add_condition_evaluation_request(EvaluationRequest * req, Context * ctx, BreakpointInfo * bp) {
    int i;
    ConditionEvaluationRequest * c = NULL;

    assert(bp->instruction_cnt);
    assert(bp->error == NULL);

    for (i = 0; i < req->bp_cnt; i++) {
        if (req->bp_arr[i].ctx == ctx && req->bp_arr[i].bp == bp) return NULL;
    }

    if (req->bp_max <= req->bp_cnt) {
        req->bp_max = req->bp_cnt + 4;
        req->bp_arr = (ConditionEvaluationRequest *)loc_realloc(req->bp_arr, sizeof(ConditionEvaluationRequest) * req->bp_max);
    }
    c = req->bp_arr + req->bp_cnt++;
    context_lock(c->ctx = ctx);
    c->bp = bp;
    c->condition_ok = 0;
    c->triggered = 0;
    return c;
}

static void post_evaluation_request(EvaluationRequest * req) {
    if (list_is_empty(&req->link_posted)) {
        context_lock(req->ctx);
        list_add_last(&req->link_posted, &evaluations_posted);
        post_safe_event(req->ctx, event_replant_breakpoints, (void *)++generation_posted);
    }
}

static void post_location_evaluation_request(Context * ctx, BreakpointInfo * bp) {
    ContextExtensionBP * ext = EXT(ctx);
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT);
    if (ext->bp_grp != NULL && ext->bp_grp != grp && !ext->bp_grp->exited) {
        /* The context has migrated into another breakpoint group.
         * If the old group became empty, we need to remove breakpoints in it.
         */
        int cnt = 0;
        LINK * l = context_root.next;
        while (l != &context_root) {
            Context * c = ctxl2ctxp(l);
            l = l->next;
            if (c->exited) continue;
            if (context_get_group(c, CONTEXT_GROUP_BREAKPOINT) == ext->bp_grp) cnt++;
        }
        if (cnt == 0) {
            EvaluationRequest * req = create_evaluation_request(ext->bp_grp);
            req->bp = NULL;
            req->location = 1;
            post_evaluation_request(req);
            EXT(ext->bp_grp)->empty_bp_grp = 1;
        }
    }
    ext->bp_grp = grp;
    if (grp != NULL) {
        EvaluationRequest * req = create_evaluation_request(grp);
        if (!req->location) {
            req->bp = bp;
            req->location = 1;
            post_evaluation_request(req);
        }
        else if (req->bp != bp) {
            assert(!list_is_empty(&req->link_posted));
            req->bp = NULL;
        }
        EXT(grp)->empty_bp_grp = 0;
    }
}

static void expr_cache_enter(CacheClient * client, BreakpointInfo * bp, Context * ctx, int index) {
    int cnt = 0;
    EvaluationArgs args;

    if (*bp->id && list_is_empty(&bp->link_clients)) return;

    args.bp = bp;
    args.ctx = ctx;
    args.index = index;

    if (*bp->id) {
        LINK * l = bp->link_clients.next;
        while (l != &bp->link_clients) {
            BreakpointRef * br = link_bp2br(l);
            Channel * c = br->channel;
            assert(br->bp == bp);
            if (c != NULL) {
                assert(!is_channel_closed(c));
                run_ctrl_lock();
                cache_enter_cnt++;
                args.in_cache = 1;
                cache_enter(client, c, &args, sizeof(args));
                cnt++;
            }
            l = l->next;
        }
    }
#if ENABLE_LineNumbersProxy && ENABLE_SymbolsProxy
    if (cnt == 0) {
        LINK * l = channel_root.next;
        while (l != &channel_root) {
            Channel * c = chanlink2channelp(l);
            if (!is_channel_closed(c)) {
                int i;
                int has_symbols = 0;
                int has_line_numbers = 0;
                for (i = 0; i < c->peer_service_cnt; i++) {
                    char * nm = c->peer_service_list[i];
                    if (strcmp(nm, "Symbols") == 0) has_symbols = 1;
                    if (strcmp(nm, "LineNumbers") == 0) has_line_numbers = 1;
                }
                if (has_symbols && has_line_numbers) {
                    run_ctrl_lock();
                    cache_enter_cnt++;
                    args.in_cache = 1;
                    cache_enter(client, c, &args, sizeof(args));
                    cnt++;
                }
            }
            l = l->next;
        }
    }
#endif
    if (cnt == 0) {
        cache_enter_cnt++;
        run_ctrl_lock();
        args.in_cache = 0;
        client(&args);
    }
}

static void free_bp(BreakpointInfo * bp) {
    assert(list_is_empty(&evaluations_posted));
    assert(list_is_empty(&evaluations_active));
    assert(list_is_empty(&bp->link_clients));
    assert(bp->instruction_cnt == 0);
    assert(bp->client_cnt == 0);
    reset_bp_hit_count(bp);
    list_remove(&bp->link_all);
    if (*bp->id) list_remove(&bp->link_id);
    if (bp->ctx) context_unlock(bp->ctx);
    release_error_report(bp->error);
    loc_free(bp->type);
    loc_free(bp->location);
    loc_free(bp->context_ids);
    loc_free(bp->context_names);
    loc_free(bp->context_query);
    loc_free(bp->stop_group);
    loc_free(bp->file);
    loc_free(bp->condition);
    loc_free(bp->client_data);
    while (bp->attrs != NULL) {
        BreakpointAttribute * attr = bp->attrs;
        bp->attrs = attr->next;
        loc_free(attr->name);
        loc_free(attr->value);
        loc_free(attr);
    }
    loc_free(bp);
}

static void remove_ref(BreakpointRef * br);
static void send_event_context_removed(BreakpointInfo * bp);
static int check_context_ids_location(BreakpointInfo * bp, Context * ctx);

static void notify_breakpoint_status(BreakpointInfo * bp) {
    assert(generation_done == generation_posted);
#ifndef NDEBUG
    {
        /* Verify breakpoints data structure */
        LINK * m = NULL;
        int instruction_cnt = 0;
        for (m = instructions.next; m != &instructions; m = m->next) {
            int i;
            BreakInstruction * bi = link_all2bi(m);
            assert(bi->valid);
            assert(bi->ref_cnt <= bi->ref_size);
            assert(bi->cb.ctx->ref_count > 0);
            for (i = 0; i < bi->ref_cnt; i++) {
                assert(bi->refs[i].cnt > 0);
                if (bi->refs[i].bp == bp) {
                    instruction_cnt++;
                    assert(check_context_ids_location(bp, bi->refs[i].ctx));
                }
            }
        }
        assert(bp->enabled || instruction_cnt == 0);
        assert(bp->instruction_cnt == instruction_cnt);
        if (*bp->id) {
            int i;
            int client_cnt = 0;
            for (i = 0; i < INP2BR_HASH_SIZE; i++) {
                for (m = inp2br[i].next; m != &inp2br[i]; m = m->next) {
                    BreakpointRef * br = link_inp2br(m);
                    if (br->bp == bp) client_cnt++;
                }
            }
            assert(bp->client_cnt == client_cnt);
        }
        else {
            assert(list_is_empty(&bp->link_clients));
        }
    }
#endif
    if (bp->client_cnt == 0) {
        if (bp->instruction_cnt == 0) {
            if (*bp->id) send_event_context_removed(bp);
            free_bp(bp);
        }
    }
    else if (bp->status_changed) {
        if (*bp->id) send_event_breakpoint_status(NULL, bp);
        bp->status_changed = 0;
    }
}

static void done_replanting_breakpoints(void) {
    LINK * l = NULL;
    assert(list_is_empty(&evaluations_posted));
    assert(list_is_empty(&evaluations_active));
    assert(generation_done == generation_active);
    for (l = breakpoints.next; l != &breakpoints;) {
        BreakpointInfo * bp = link_all2bp(l);
        l = l->next;
        bp->attrs_changed = 0;
        notify_breakpoint_status(bp);
    }
}

static void done_condition_evaluation(EvaluationRequest * req) {
    Context ** trig_ctx = (Context **)tmp_alloc_zero(sizeof(Context *) * req->bp_cnt);
    size_t * trig_size = (size_t *)tmp_alloc_zero(sizeof(size_t) * req->bp_cnt);
    int trig_cnt = 0;
    int i, j;

    for (i = 0; i < req->bp_cnt; i++) {
        Context * ctx = req->bp_arr[i].ctx;
        BreakpointInfo * bp = req->bp_arr[i].bp;
        assert(ctx->stopped);
        if (!req->bp_arr[i].condition_ok) continue;
        if (inc_bp_hit_count(bp, req->ctx) <= bp->ignore_count) continue;
        if (bp->event_callback != NULL) {
            bp->event_callback(ctx, bp->event_callback_args);
        }
        else {
            j = 0;
            assert(bp->id[0] != 0);
            req->bp_arr[i].triggered = 1;
            while (j < trig_cnt && trig_ctx[j] != ctx) j++;
            if (j == trig_cnt) trig_ctx[trig_cnt++] = ctx;
            trig_size[j] += sizeof(char *) + strlen(bp->id) + 1;
        }
    }

    for (j = 0; j < trig_cnt; j++) {
        /* Create list of triggered breakpoint IDs */
        Context * ctx = trig_ctx[j];
        size_t mem_size = trig_size[j] + sizeof(char *);
        char ** bp_id_list = (char **)loc_alloc(mem_size);
        char * pool = (char *)bp_id_list + mem_size;
        ContextExtensionBP * ext = EXT(ctx);
        assert(ext->bp_ids == NULL);
        ext->bp_ids = bp_id_list;
        for (i = 0; i < req->bp_cnt; i++) {
            if (req->bp_arr[i].triggered && req->bp_arr[i].ctx == ctx) {
                BreakpointInfo * bp = req->bp_arr[i].bp;
                size_t n = strlen(bp->id) + 1;
                pool -= n;
                memcpy(pool, bp->id, n);
                *bp_id_list++ = pool;
            }
        }
        *bp_id_list++ = NULL;
        assert((char *)bp_id_list == pool);
    }

    /* Intercept contexts */
    for (i = 0; i < req->bp_cnt; i++) {
        if (req->bp_arr[i].triggered && req->bp_arr[i].bp->stop_group == NULL) {
            suspend_debug_context(req->bp_arr[i].ctx);
        }
    }
}

static void done_all_evaluations(void) {
    LINK * l = evaluations_active.next;

    while (l != &evaluations_active) {
        EvaluationRequest * req = link_active2erl(l);
        l = l->next;
        if (req->bp_cnt) done_condition_evaluation(req);
    }

    l = evaluations_active.next;
    while (l != &evaluations_active) {
        EvaluationRequest * req = link_active2erl(l);
        int i;

        l = l->next;

        for (i = 0; i < req->bp_cnt; i++) {
            if (req->bp_arr[i].triggered) {
                BreakpointInfo * bp = req->bp_arr[i].bp;
                if (bp->stop_group != NULL) {
                    /* Intercept contexts in BP stop groups */
                    char ** ids = bp->stop_group;
                    while (*ids) {
                        Context * c = id2ctx(*ids++);
                        if (c != NULL) suspend_debug_context(c);
                    }
                }
                if (bp->temporary) {
                    LINK * m = bp->link_clients.next;
                    while (m != &bp->link_clients) {
                        BreakpointRef * br = link_bp2br(m);
                        m = m->next;
                        assert(br->bp == bp);
                        remove_ref(br);
                    }
                }
            }
            context_unlock(req->bp_arr[i].ctx);
        }

        req->bp_cnt = 0;
        list_remove(&req->link_active);
        context_unlock(req->ctx);
    }

    if (list_is_empty(&evaluations_posted)) {
        assert(cache_enter_cnt == 0);
        assert(generation_done != generation_active);
        flush_instructions();
        generation_done = generation_active;
        done_replanting_breakpoints();
    }
}

static void done_evaluation(void) {
    assert(cache_enter_cnt > 0);
    cache_enter_cnt--;
    if (cache_enter_cnt == 0) {
        done_all_evaluations();
        if (!list_is_empty(&evaluations_posted)) {
            EvaluationRequest * req = link_posted2erl(evaluations_posted.next);
            post_safe_event(req->ctx, event_replant_breakpoints, (void *)++generation_posted);
        }
    }
}

static void expr_cache_exit(EvaluationArgs * args) {
    if (args->in_cache) cache_exit();
    done_evaluation();
    run_ctrl_unlock();
}

static void plant_at_address_expression(Context * ctx, ContextAddress ip, BreakpointInfo * bp) {
    ContextAddress addr = 0;
    ContextAddress size = 1;
    int error = 0;
    Value v;

    if (evaluate_expression(ctx, STACK_NO_FRAME, ip, bp->location, 1, &v) < 0) error = errno;
    if (!error && value_to_address(&v, &addr) < 0) error = errno;
    if (bp->access_mode & (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_DATA_WRITE)) {
        if (bp->access_size > 0) {
            size = bp->access_size;
        }
        else {
            size = context_word_size(ctx);
#if ENABLE_Symbols
            {
                Symbol * type = v.type;
                if (type != NULL) {
                    int type_class = 0;
                    Symbol * base_type = NULL;
                    if (!error && get_symbol_type_class(type, &type_class) < 0) error = errno;
                    if (!error && type_class != TYPE_CLASS_POINTER) error = set_errno(ERR_INV_DATA_TYPE, "Pointer expected");
                    if (!error && get_symbol_base_type(type, &base_type) < 0) error = errno;
                    if (!error && base_type != NULL && get_symbol_size(base_type, &size) < 0) error = errno;
                }
            }
#endif
        }
    }
    if (error) address_expression_error(ctx, bp, error);
    else plant_breakpoint(ctx, bp, addr, size);
}

#if ENABLE_LineNumbers
static void plant_breakpoint_address_iterator(CodeArea * area, void * x) {
    EvaluationArgs * args = (EvaluationArgs *)x;
    if (args->bp->location == NULL) {
        ContextAddress addr = area->start_address;
        if ((addr == 0 || area->start_line != args->bp->line) && area->next_address != 0) addr = area->next_address;
        plant_breakpoint(args->ctx, args->bp, addr, 1);
    }
    else {
        plant_at_address_expression(args->ctx, area->start_address, args->bp);
    }
}
#endif

static int check_context_ids_location(BreakpointInfo * bp, Context * ctx) {
    /* Check context IDs attribute and return 1 if the breakpoint should be planted in 'ctx' */
    assert(ctx == context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
    if (bp->ctx != NULL) {
        if (context_get_group(bp->ctx, CONTEXT_GROUP_BREAKPOINT) != ctx) return 0;
    }
    if (bp->context_ids != NULL) {
        int ok = 0;
        char ** ids = bp->context_ids;
        while (!ok && *ids != NULL) {
            Context * c = id2ctx(*ids++);
            if (c == NULL) continue;
            ok = context_get_group(c, CONTEXT_GROUP_BREAKPOINT) == ctx;
        }
        if (!ok) return 0;
    }
    if (bp->context_names != NULL) {
        int ok = 0;
        char ** names = bp->context_names;
        while (!ok && *names != NULL) {
            char * name = *names++;
            LINK * l = context_root.next;
            while (!ok && l != &context_root) {
                Context * c = ctxl2ctxp(l);
                l = l->next;
                if (c->exited) continue;
                if (c->name == NULL) continue;
                if (context_get_group(c, CONTEXT_GROUP_BREAKPOINT) != ctx) continue;
                ok = strcmp(c->name, name) == 0;
            }
        }
        if (!ok) return 0;
    }
    if (bp->context_query != NULL) {
        int ok = 0;
        LINK * l = context_root.next;
        if (parse_context_query(bp->context_query) < 0) {
            bp_location_error = get_error_report(errno);
            return 0;
        }
        while (!ok && l != &context_root) {
            Context * c = ctxl2ctxp(l);
            l = l->next;
            if (c->exited) continue;
            if (context_get_group(c, CONTEXT_GROUP_BREAKPOINT) != ctx) continue;
            ok = run_context_query(c);
        }
        if (!ok) return 0;
    }
    return 1;
}

static int check_context_ids_condition(BreakpointInfo * bp, Context * ctx) {
    /* Check context IDs attribute and return 1 if the breakpoint should be triggered by 'ctx' */
    assert(context_has_state(ctx));
    if (bp->ctx != NULL) {
        if (bp->ctx != ctx) return 0;
    }
    if (bp->context_ids != NULL) {
        int ok = 0;
        char ** ids = bp->context_ids;
        Context * prs = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
        while (!ok && *ids != NULL) {
            char * id = *ids++;
            ok = strcmp(id, ctx->id) == 0 || (prs && strcmp(id, prs->id) == 0);
        }
        if (!ok) return 0;
    }
    if (bp->context_names != NULL) {
        int ok = 0;
        if (ctx->name) {
            char * name = ctx->name;
            char ** names = bp->context_names;
            while (!ok && *names != NULL) {
                ok = strcmp(name, *names++) == 0;
            }
        }
        if (!ok) {
            Context * prs = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
            if (prs && prs->name) {
                char * name = prs->name;
                char ** names = bp->context_names;
                while (!ok && *names != NULL) {
                    ok = strcmp(name, *names++) == 0;
                }
            }
        }
        if (!ok) return 0;
    }
    if (bp->context_query != NULL) {
        parse_context_query(bp->context_query);
        if (!run_context_query(ctx)) return 0;
    }
    return 1;
}

static void evaluate_condition(void * x) {
    EvaluationArgs * args = (EvaluationArgs *)x;
    EvaluationRequest * req = EXT(args->ctx)->req;
    ConditionEvaluationRequest * ce = req->bp_arr + args->index;
    BreakpointInfo * bp = ce->bp;

    assert(req != NULL);
    assert(req->bp_cnt > 0);
    assert(args->index >= 0);
    assert(args->index < req->bp_cnt);
    assert(cache_enter_cnt > 0);
    assert(args->bp == ce->bp);

    if (!is_disabled(bp)) {
        Context * ctx = ce->ctx;
        assert(ctx->stopped);
        assert(ctx->stopped_by_bp || ctx->stopped_by_cb);

        if (check_context_ids_condition(bp, ctx)) {
            if (bp->condition != NULL) {
                Value v;
                int b = 0;
                if (evaluate_expression(ctx, STACK_TOP_FRAME, 0, bp->condition, 1, &v) < 0 || value_to_boolean(&v, &b) < 0) {
                    switch (get_error_code(errno)) {
                    case ERR_CACHE_MISS:
                    case ERR_CHANNEL_CLOSED:
                        break;
                    default:
                        trace(LOG_ALWAYS, "%s: %s", errno_to_str(errno), bp->condition);
                        ce->condition_ok = 1;
                        break;
                    }
                }
                else if (b) {
                    ce->condition_ok = 1;
                }
            }
            else {
                ce->condition_ok = 1;
            }
        }
    }

    expr_cache_exit(args);
}

static void evaluate_bp_location(void * x) {
    EvaluationArgs * args = (EvaluationArgs *)x;
    BreakpointInfo * bp = args->bp;
    Context * ctx = args->ctx;

    assert(cache_enter_cnt > 0);
    if (bp_location_error != NULL) {
        release_error_report(bp_location_error);
        bp_location_error = NULL;
    }
    if (!ctx->exited && !ctx->exiting && !EXT(ctx)->empty_bp_grp &&
            !is_disabled(bp) && check_context_ids_location(bp, ctx)) {
        if (bp->file != NULL) {
#if ENABLE_LineNumbers
            if (line_to_address(ctx, bp->file, bp->line, bp->column, plant_breakpoint_address_iterator, args) < 0) {
                address_expression_error(ctx, bp, errno);
            }
#else
            set_errno(ERR_UNSUPPORTED, "LineNumbers service not available");
            bp_location_error = get_error_report(errno);
#endif
        }
        else if (bp->location != NULL) {
            plant_at_address_expression(ctx, 0, bp);
        }
        else {
            link_breakpoint_instruction(bp, ctx, 0, bp->access_size, NULL, 0, 0, NULL);
        }
    }
    expr_cache_exit(args);
    if (!compare_error_reports(bp_location_error, bp->error)) {
        release_error_report(bp->error);
        bp->error = bp_location_error;
        bp->status_changed = 1;
    }
    else {
        release_error_report(bp_location_error);
    }
    bp_location_error = NULL;
}

static void event_replant_breakpoints(void * arg) {
    LINK * q;

    assert(!list_is_empty(&evaluations_posted));
    if ((uintptr_t)arg != generation_posted) return;
    if (cache_enter_cnt > 0) return;

    assert(list_is_empty(&evaluations_active));
    cache_enter_cnt++;
    generation_active = generation_posted;
    q = evaluations_posted.next;
    while (q != &evaluations_posted) {
        EvaluationRequest * req = link_posted2erl(q);
        Context * ctx = req->ctx;
        q = q->next;
        list_remove(&req->link_posted);
        list_add_first(&req->link_active, &evaluations_active);
        if (req->location) {
            BreakpointInfo * bp = req->bp;
            req->location = 0;
            req->bp = NULL;
            clear_instruction_refs(ctx, bp);
            if (!ctx->exiting && !ctx->exited && !EXT(ctx)->empty_bp_grp) {
                context_lock(ctx);
                if (bp != NULL) {
                    expr_cache_enter(evaluate_bp_location, bp, ctx, -1);
                }
                else {
                    LINK * l = breakpoints.next;
                    while (l != &breakpoints) {
                        expr_cache_enter(evaluate_bp_location, link_all2bp(l), ctx, -1);
                        l = l->next;
                    }
                }
                context_unlock(ctx);
            }
        }
        if (req->bp_cnt > 0) {
            int i;
            for (i = 0; i < req->bp_cnt; i++) {
                ConditionEvaluationRequest * r = req->bp_arr + i;
                r->condition_ok = 0;
                if (is_disabled(r->bp)) continue;
                expr_cache_enter(evaluate_condition, r->bp, ctx, i);
            }
        }
    }
    done_evaluation();
}

static void replant_breakpoint(BreakpointInfo * bp) {
    int check_intsructions = 0;
    if (bp->client_cnt == 0) {
        check_intsructions = 1;
    }
    else if (bp->ctx != NULL) {
        post_location_evaluation_request(bp->ctx, bp);
    }
    else if (bp->context_ids) {
        char ** ids = bp->context_ids;
        while (*ids != NULL) {
            Context * ctx = id2ctx(*ids++);
            if (ctx == NULL) continue;
            if (ctx->exited) continue;
            post_location_evaluation_request(ctx, bp);
        }
        check_intsructions = 1;
    }
    else if (bp->context_names) {
        char ** names = bp->context_names;
        while (*names != NULL) {
            char * name = *names++;
            LINK * l = context_root.next;
            while (l != &context_root) {
                Context * ctx = ctxl2ctxp(l);
                l = l->next;
                if (ctx->exited) continue;
                if (ctx->name == NULL) continue;
                if (strcmp(ctx->name, name)) continue;
                post_location_evaluation_request(ctx, bp);
            }
        }
        check_intsructions = 1;
    }
    else if (bp->context_query && parse_context_query(bp->context_query) == 0) {
        LINK * l = context_root.next;
        while (l != &context_root) {
            Context * ctx = ctxl2ctxp(l);
            l = l->next;
            if (ctx->exited) continue;
            if (!run_context_query(ctx)) continue;
            post_location_evaluation_request(ctx, bp);
        }
        check_intsructions = 1;
    }
    else {
        LINK * l = context_root.next;
        while (l != &context_root) {
            Context * ctx = ctxl2ctxp(l);
            l = l->next;
            if (ctx->exited) continue;
            post_location_evaluation_request(ctx, bp);
        }
    }
    if (check_intsructions && bp->instruction_cnt > 0) {
        LINK * l = instructions.next;
        while (l != &instructions) {
            int i;
            BreakInstruction * bi = link_all2bi(l);
            for (i = 0; i < bi->ref_cnt; i++) {
                InstructionRef * ref = bi->refs + i;
                if (ref->bp != bp) continue;
                post_location_evaluation_request(ref->ctx, bp);
            }
            l = l->next;
        }
    }
}

static BreakpointInfo * find_breakpoint(char * id) {
    int hash = id2bp_hash(id);
    LINK * l = id2bp[hash].next;
    while (l != id2bp + hash) {
        BreakpointInfo * bp = link_id2bp(l);
        l = l->next;
        if (strcmp(bp->id, id) == 0) return bp;
    }
    return NULL;
}

static BreakpointRef * find_breakpoint_ref(BreakpointInfo * bp, Channel * channel) {
    LINK * l;
    if (bp == NULL) return NULL;
    l = bp->link_clients.next;
    while (l != &bp->link_clients) {
        BreakpointRef * br = link_bp2br(l);
        assert(br->bp == bp);
        if (br->channel == channel) return br;
        l = l->next;
    }
    return NULL;
}

static BreakpointAttribute * read_breakpoint_properties(InputStream * inp) {
    BreakpointAttribute * attrs = NULL;
    if (read_stream(inp) != '{') exception(ERR_JSON_SYNTAX);
    if (peek_stream(inp) == '}') {
        read_stream(inp);
    }
    else {
        BreakpointAttribute ** p = &attrs;
        for (;;) {
            int ch;
            char name[256];
            BreakpointAttribute * attr = (BreakpointAttribute *)loc_alloc_zero(sizeof(BreakpointAttribute));

            json_read_string(inp, name, sizeof(name));
            if (read_stream(inp) != ':') exception(ERR_JSON_SYNTAX);
            attr->name = loc_strdup(name);
            attr->value = json_read_object(inp);
            *p = attr;
            p = &attr->next;

            ch = read_stream(inp);
            if (ch == ',') continue;
            if (ch == '}') break;
            exception(ERR_JSON_SYNTAX);
        }
    }
    return attrs;
}

static void read_id_attribute(BreakpointAttribute * attrs, char * id, size_t id_size) {
    while (attrs != NULL) {
        if (strcmp(attrs->name, BREAKPOINT_ID) == 0) {
            ByteArrayInputStream buf;
            InputStream * inp = create_byte_array_input_stream(&buf, attrs->value, strlen(attrs->value));
            json_read_string(inp, id, id_size);
            if (read_stream(inp) != MARKER_EOS) exception(ERR_JSON_SYNTAX);
            return;
        }
        attrs = attrs->next;
    }
    str_exception(ERR_OTHER, "Breakpoint must have an ID");
}

static void set_breakpoint_attribute(BreakpointInfo * bp, const char * name, const char * value) {
    BreakpointAttribute * attr = bp->attrs;
    BreakpointAttribute ** ref = &bp->attrs;

    while (attr != NULL) {
        if (strcmp(attr->name, name) == 0) {
            loc_free(attr->value);
            attr->value = loc_strdup(value);
            return;
        }
        ref = &attr->next;
        attr = attr->next;
    }
    attr = (BreakpointAttribute *)loc_alloc_zero(sizeof(BreakpointAttribute));
    attr->name = loc_strdup(name);
    attr->value = loc_strdup(value);
    *ref = attr;
}

static int set_breakpoint_attributes(BreakpointInfo * bp, BreakpointAttribute * new_attrs) {
    int diff = 0;
    BreakpointAttribute * old_attrs = bp->attrs;
    BreakpointAttribute ** new_ref = &bp->attrs;
    bp->attrs = NULL;

    while (new_attrs != NULL) {
        BreakpointAttribute * new_attr = new_attrs;
        BreakpointAttribute * old_attr = old_attrs;
        BreakpointAttribute ** old_ref = &old_attrs;
        InputStream * buf_inp = NULL;
        ByteArrayInputStream buf;
        int unsupported_attr = 0;
        char * name = new_attr->name;

        new_attrs = new_attr->next;
        new_attr->next = NULL;
        while (old_attr && strcmp(old_attr->name, name)) {
            old_ref = &old_attr->next;
            old_attr = old_attr->next;
        }

        if (old_attr != NULL) {
            assert(old_attr == *old_ref);
            *old_ref = old_attr->next;
            old_attr->next = NULL;
            if (strcmp(old_attr->value, new_attr->value) == 0) {
                *new_ref = old_attr;
                new_ref = &old_attr->next;
                loc_free(new_attr->value);
                loc_free(new_attr->name);
                loc_free(new_attr);
                continue;
            }
            loc_free(old_attr->value);
            loc_free(old_attr->name);
            loc_free(old_attr);
            old_attr = NULL;
        }
        diff++;

        *new_ref = new_attr;
        new_ref = &new_attr->next;

        buf_inp = create_byte_array_input_stream(&buf, new_attr->value, strlen(new_attr->value));

        if (strcmp(name, BREAKPOINT_ID) == 0) {
            json_read_string(buf_inp, bp->id, sizeof(bp->id));
        }
        else if (strcmp(name, BREAKPOINT_TYPE) == 0) {
            loc_free(bp->type);
            bp->type = json_read_alloc_string(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_LOCATION) == 0) {
            loc_free(bp->location);
            bp->location = json_read_alloc_string(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_ACCESSMODE) == 0) {
            bp->access_mode = json_read_long(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_SIZE) == 0) {
            bp->access_size = json_read_long(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_CONDITION) == 0) {
            loc_free(bp->condition);
            bp->condition = json_read_alloc_string(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_CONTEXTIDS) == 0) {
            loc_free(bp->context_ids);
            bp->context_ids = json_read_alloc_string_array(buf_inp, NULL);
        }
        else if (strcmp(name, BREAKPOINT_CONTEXTNAMES) == 0) {
            loc_free(bp->context_names);
            bp->context_names = json_read_alloc_string_array(buf_inp, NULL);
        }
        else if (strcmp(name, BREAKPOINT_CONTEXT_QUERY) == 0) {
            loc_free(bp->context_query);
            bp->context_query = json_read_alloc_string(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_STOP_GROUP) == 0) {
            loc_free(bp->stop_group);
            bp->stop_group = json_read_alloc_string_array(buf_inp, NULL);
        }
        else if (strcmp(name, BREAKPOINT_TEMPORARY) == 0) {
            bp->temporary = json_read_boolean(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_FILE) == 0) {
            loc_free(bp->file);
            bp->file = json_read_alloc_string(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_LINE) == 0) {
            bp->line = json_read_long(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_COLUMN) == 0) {
            bp->column = json_read_long(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_IGNORECOUNT) == 0) {
            bp->ignore_count = json_read_ulong(buf_inp);
        }
        else if (strcmp(name, BREAKPOINT_ENABLED) == 0) {
            bp->enabled = json_read_boolean(buf_inp);
        }
        else {
            unsupported_attr = 1;
        }

        if (!unsupported_attr && read_stream(buf_inp) != MARKER_EOS) exception(ERR_JSON_SYNTAX);
    }

    while (old_attrs != NULL) {
        BreakpointAttribute * old_attr = old_attrs;
        char * name = old_attr->name;
        old_attrs = old_attr->next;

        if (strcmp(name, BREAKPOINT_ID) == 0) {
            bp->id[0] = 0;
        }
        else if (strcmp(name, BREAKPOINT_TYPE) == 0) {
            loc_free(bp->type);
            bp->type = NULL;
        }
        else if (strcmp(name, BREAKPOINT_LOCATION) == 0) {
            loc_free(bp->location);
            bp->location = NULL;
        }
        else if (strcmp(name, BREAKPOINT_ACCESSMODE) == 0) {
            bp->access_mode = 0;
        }
        else if (strcmp(name, BREAKPOINT_SIZE) == 0) {
            bp->access_size = 0;
        }
        else if (strcmp(name, BREAKPOINT_CONDITION) == 0) {
            loc_free(bp->condition);
            bp->condition = NULL;
        }
        else if (strcmp(name, BREAKPOINT_CONTEXTIDS) == 0) {
            loc_free(bp->context_ids);
            bp->context_ids = NULL;
        }
        else if (strcmp(name, BREAKPOINT_CONTEXTNAMES) == 0) {
            loc_free(bp->context_names);
            bp->context_names = NULL;
        }
        else if (strcmp(name, BREAKPOINT_CONTEXT_QUERY) == 0) {
            loc_free(bp->context_query);
            bp->context_query = NULL;
        }
        else if (strcmp(name, BREAKPOINT_STOP_GROUP) == 0) {
            loc_free(bp->stop_group);
            bp->stop_group = NULL;
        }
        else if (strcmp(name, BREAKPOINT_TEMPORARY) == 0) {
            bp->temporary = 0;
        }
        else if (strcmp(name, BREAKPOINT_FILE) == 0) {
            loc_free(bp->file);
            bp->file = NULL;
        }
        else if (strcmp(name, BREAKPOINT_LINE) == 0) {
            bp->line = 0;
        }
        else if (strcmp(name, BREAKPOINT_COLUMN) == 0) {
            bp->column = 0;
        }
        else if (strcmp(name, BREAKPOINT_IGNORECOUNT) == 0) {
            bp->ignore_count = 0;
        }
        else if (strcmp(name, BREAKPOINT_ENABLED) == 0) {
            bp->enabled = 0;
        }

        loc_free(old_attr->value);
        loc_free(old_attr->name);
        loc_free(old_attr);
        diff++;
    }

    return diff;
}

static void write_breakpoint_properties(OutputStream * out, BreakpointInfo * bp) {
    int cnt = 0;
    BreakpointAttribute * attr = bp->attrs;

    write_stream(out, '{');

    while (attr != NULL) {
        if (cnt > 0) write_stream(out, ',');
        json_write_string(out, attr->name);
        write_stream(out, ':');
        write_string(out, attr->value);
        attr = attr->next;
        cnt++;
    }

    write_stream(out, '}');
}

static void send_event_context_added(Channel * channel, BreakpointInfo * bp) {
    OutputStream * out = channel ? &channel->out : &broadcast_group->out;
    unsigned i;

    write_stringz(out, "E");
    write_stringz(out, BREAKPOINTS);
    write_stringz(out, "contextAdded");

    write_stream(out, '[');
    write_breakpoint_properties(out, bp);
    write_stream(out, ']');
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);
    if (channel) return;

    for (i = 0; i < listener_cnt; i++) {
        Listener * l = listeners + i;
        if (l->listener->breakpoint_created == NULL) continue;
        l->listener->breakpoint_created(bp, l->args);
    }
}

static void send_event_context_changed(BreakpointInfo * bp) {
    OutputStream * out = &broadcast_group->out;
    unsigned i;

    write_stringz(out, "E");
    write_stringz(out, BREAKPOINTS);
    write_stringz(out, "contextChanged");

    write_stream(out, '[');
    write_breakpoint_properties(out, bp);
    write_stream(out, ']');
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);

    for (i = 0; i < listener_cnt; i++) {
        Listener * l = listeners + i;
        if (l->listener->breakpoint_changed == NULL) continue;
        l->listener->breakpoint_changed(bp, l->args);
    }
}

static void send_event_context_removed(BreakpointInfo * bp) {
    OutputStream * out = &broadcast_group->out;
    unsigned i;

    write_stringz(out, "E");
    write_stringz(out, BREAKPOINTS);
    write_stringz(out, "contextRemoved");

    write_stream(out, '[');
    json_write_string(out, bp->id);
    write_stream(out, ']');
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);

    for (i = 0; i < listener_cnt; i++) {
        Listener * l = listeners + i;
        if (l->listener->breakpoint_deleted == NULL) continue;
        l->listener->breakpoint_deleted(bp, l->args);
    }
}

static BreakpointInfo * add_breakpoint(Channel * c, BreakpointAttribute * attrs) {
    char id[256];
    BreakpointRef * r = NULL;
    BreakpointInfo * bp = NULL;
    int ref_added = 0;
    int added = 0;
    int chng = 0;

    read_id_attribute(attrs, id, sizeof(id));
    bp = find_breakpoint(id);
    if (bp == NULL) {
        int hash = id2bp_hash(id);
        bp = (BreakpointInfo *)loc_alloc_zero(sizeof(BreakpointInfo));
        list_init(&bp->link_clients);
        list_init(&bp->link_hit_count);
        list_add_last(&bp->link_all, &breakpoints);
        list_add_last(&bp->link_id, id2bp + hash);
    }
    chng = set_breakpoint_attributes(bp, attrs);
    if (chng) bp->attrs_changed = 1;
    if (list_is_empty(&bp->link_clients)) added = 1;
    else r = find_breakpoint_ref(bp, c);
    if (r == NULL) {
        unsigned inp_hash = (unsigned)(uintptr_t)c / 16 % INP2BR_HASH_SIZE;
        r = (BreakpointRef *)loc_alloc_zero(sizeof(BreakpointRef));
        list_add_last(&r->link_inp, inp2br + inp_hash);
        list_add_last(&r->link_bp, &bp->link_clients);
        r->channel = c;
        r->bp = bp;
        bp->client_cnt++;
        ref_added = 1;
    }
    assert(r->bp == bp);
    assert(!list_is_empty(&bp->link_clients));
    if (chng || added || ref_added) replant_breakpoint(bp);
    if (added) send_event_context_added(NULL, bp);
    else if (chng) send_event_context_changed(bp);
    return bp;
}

static void remove_ref(BreakpointRef * br) {
    BreakpointInfo * bp = br->bp;
    bp->client_cnt--;
    list_remove(&br->link_inp);
    list_remove(&br->link_bp);
    loc_free(br);
    replant_breakpoint(bp);
    if (list_is_empty(&bp->link_clients)) {
        assert(bp->client_cnt == 0);
        if (generation_done == generation_posted) notify_breakpoint_status(bp);
    }
}

static void delete_breakpoint_refs(Channel * c) {
    unsigned hash = (unsigned)(uintptr_t)c / 16 % INP2BR_HASH_SIZE;
    LINK * l = inp2br[hash].next;
    while (l != &inp2br[hash]) {
        BreakpointRef * br = link_inp2br(l);
        l = l->next;
        if (br->channel == c) remove_ref(br);
    }
}

static void command_set(char * token, Channel * c) {
    int ch;
    LINK * l = NULL;

    /* Delete all breakpoints of this channel */
    delete_breakpoint_refs(c);

    /* Report breakpoints from other channels */
    l = breakpoints.next;
    while (l != &breakpoints) {
        BreakpointInfo * bp = link_all2bp(l);
        l = l->next;
        if (list_is_empty(&bp->link_clients)) continue;
        assert(*bp->id);
        send_event_context_added(c, bp);
        send_event_breakpoint_status(c, bp);
    }

    /* Add breakpoints for this channel */
    ch = read_stream(&c->inp);
    if (ch == 'n') {
        if (read_stream(&c->inp) != 'u') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
    }
    else {
        if (ch != '[') exception(ERR_PROTOCOL);
        if (peek_stream(&c->inp) == ']') {
            read_stream(&c->inp);
        }
        else {
            for (;;) {
                int ch;
                add_breakpoint(c, read_breakpoint_properties(&c->inp));
                ch = read_stream(&c->inp);
                if (ch == ',') continue;
                if (ch == ']') break;
                exception(ERR_JSON_SYNTAX);
            }
        }
    }
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_ids(char * token, Channel * c) {
    LINK * l = breakpoints.next;
    int cnt = 0;

    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);
    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, '[');

    while (l != &breakpoints) {
        BreakpointInfo * bp = link_all2bp(l);
        l = l->next;
        if (list_is_empty(&bp->link_clients)) continue;
        assert(*bp->id);
        if (cnt > 0) write_stream(&c->out, ',');
        json_write_string(&c->out, bp->id);
        cnt++;
    }

    write_stream(&c->out, ']');
    write_stream(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_properties(char * token, Channel * c) {
    char id[256];
    BreakpointInfo * bp = NULL;
    int err = 0;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    bp = find_breakpoint(id);
    if (bp == NULL || list_is_empty(&bp->link_clients)) err = ERR_INV_CONTEXT;

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, err);
    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        write_breakpoint_properties(&c->out, bp);
        write_stream(&c->out, 0);
    }
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_status(char * token, Channel * c) {
    char id[256];
    BreakpointInfo * bp = NULL;
    int err = 0;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    bp = find_breakpoint(id);
    if (bp == NULL || list_is_empty(&bp->link_clients)) err = ERR_INV_CONTEXT;

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, err);
    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        write_breakpoint_status(&c->out, bp);
        write_stream(&c->out, 0);
    }
    write_stream(&c->out, MARKER_EOM);
}

static void command_add(char * token, Channel * c) {
    BreakpointAttribute * props = read_breakpoint_properties(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    add_breakpoint(c, props);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_change(char * token, Channel * c) {
    BreakpointAttribute * props = read_breakpoint_properties(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    add_breakpoint(c, props);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_enable(char * token, Channel * c) {
    int ch = read_stream(&c->inp);
    if (ch == 'n') {
        if (read_stream(&c->inp) != 'u') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
    }
    else {
        if (ch != '[') exception(ERR_PROTOCOL);
        if (peek_stream(&c->inp) == ']') {
            read_stream(&c->inp);
        }
        else {
            for (;;) {
                int ch;
                char id[256];
                BreakpointInfo * bp;
                json_read_string(&c->inp, id, sizeof(id));
                bp = find_breakpoint(id);
                if (bp != NULL && !list_is_empty(&bp->link_clients) && !bp->enabled) {
                    bp->enabled = 1;
                    reset_bp_hit_count(bp);
                    set_breakpoint_attribute(bp, BREAKPOINT_ENABLED, "true");
                    replant_breakpoint(bp);
                    send_event_context_changed(bp);
                }
                ch = read_stream(&c->inp);
                if (ch == ',') continue;
                if (ch == ']') break;
                exception(ERR_JSON_SYNTAX);
            }
        }
    }
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_disable(char * token, Channel * c) {
    int ch = read_stream(&c->inp);
    if (ch == 'n') {
        if (read_stream(&c->inp) != 'u') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
    }
    else {
        if (ch != '[') exception(ERR_PROTOCOL);
        if (peek_stream(&c->inp) == ']') {
            read_stream(&c->inp);
        }
        else {
            for (;;) {
                int ch;
                char id[256];
                BreakpointInfo * bp;
                json_read_string(&c->inp, id, sizeof(id));
                bp = find_breakpoint(id);
                if (bp != NULL && !list_is_empty(&bp->link_clients) && bp->enabled) {
                    bp->enabled = 0;
                    set_breakpoint_attribute(bp, BREAKPOINT_ENABLED, "false");
                    replant_breakpoint(bp);
                    send_event_context_changed(bp);
                }
                ch = read_stream(&c->inp);
                if (ch == ',') continue;
                if (ch == ']') break;
                exception(ERR_JSON_SYNTAX);
            }
        }
    }
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_remove(char * token, Channel * c) {
    int ch = read_stream(&c->inp);
    if (ch == 'n') {
        if (read_stream(&c->inp) != 'u') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
        if (read_stream(&c->inp) != 'l') exception(ERR_JSON_SYNTAX);
    }
    else {
        if (ch != '[') exception(ERR_PROTOCOL);
        if (peek_stream(&c->inp) == ']') {
            read_stream(&c->inp);
        }
        else {
            for (;;) {
                int ch;
                char id[256];
                BreakpointRef * br;
                json_read_string(&c->inp, id, sizeof(id));
                br = find_breakpoint_ref(find_breakpoint(id), c);
                if (br != NULL) remove_ref(br);
                ch = read_stream(&c->inp);
                if (ch == ',') continue;
                if (ch == ']') break;
                exception(ERR_JSON_SYNTAX);
            }
        }
    }
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_capabilities(char * token, Channel * c) {
    char id[256];
    Context * ctx;
    OutputStream * out = &c->out;
    int err = 0;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    ctx = id2ctx(id);
    if ((strlen(id)>0) && !ctx) err = ERR_INV_CONTEXT;

    write_stringz(out, "R");
    write_stringz(out, token);
    write_errno(out, err);
    if (err) {
        write_stringz(&c->out, "null");
    }
    else {
        write_stream(out, '{');
        json_write_string(out, "ID");
        write_stream(out, ':');
        json_write_string(out, id);
        write_stream(out, ',');
        json_write_string(out, "BreakpointType");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        write_stream(out, ',');
        json_write_string(out, "Location");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        write_stream(out, ',');
        json_write_string(out, "FileLine");
        write_stream(out, ':');
        json_write_boolean(out, ENABLE_LineNumbers);
        write_stream(out, ',');
        json_write_string(out, "FileMapping");
        write_stream(out, ':');
        json_write_boolean(out, SERVICE_PathMap);
        write_stream(out, ',');
        json_write_string(out, "IgnoreCount");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        write_stream(out, ',');
        json_write_string(out, "Condition");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        if (ctx != NULL) {
            int md = CTX_BP_ACCESS_INSTRUCTION;
            md |= context_get_supported_bp_access_types(ctx);
            md &= ~CTX_BP_ACCESS_VIRTUAL;
            write_stream(out, ',');
            json_write_string(out, "AccessMode");
            write_stream(out, ':');
            json_write_long(out, md);
        }
        write_stream(out, ',');
        json_write_string(out, "ContextIds");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        write_stream(out, ',');
        json_write_string(out, "ContextNames");
        write_stream(out, ':');
        json_write_boolean(out, 1);
#if SERVICE_ContextQuery
        write_stream(out, ',');
        json_write_string(out, "ContextQuery");
        write_stream(out, ':');
        json_write_boolean(out, 1);
#endif
        write_stream(out, ',');
        json_write_string(out, "StopGroup");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        write_stream(out, ',');
        json_write_string(out, "ClientData");
        write_stream(out, ':');
        json_write_boolean(out, 1);
        write_stream(out, ',');
        json_write_string(out, "Temporary");
        write_stream(out, ':');
        json_write_boolean(out, 1);
#if ENABLE_ContextBreakpointCapabilities
        {
            /* Back-end context breakpoint capabilities */
            int cnt = 0;
            const char ** names = NULL;
            const char ** values = NULL;
            if (context_get_breakpoint_capabilities(ctx, &names, &values, &cnt) == 0) {
                while (cnt > 0) {
                    if (*values != NULL) {
                        write_stream(out, ',');
                        json_write_string(out, *names);
                        write_stream(out, ':');
                        write_string(out, *values);
                    }
                    names++;
                    values++;
                    cnt--;
                }
            }
        }
#endif
        write_stream(out, '}');
        write_stream(out, 0);
    }

    write_stream(out, MARKER_EOM);
}

void add_breakpoint_event_listener(BreakpointsEventListener * listener, void * args) {
    if (listener_cnt >= listener_max) {
        listener_max += 8;
        listeners = (Listener *)loc_realloc(listeners, listener_max * sizeof(Listener));
    }
    listeners[listener_cnt].listener = listener;
    listeners[listener_cnt].args = args;
    listener_cnt++;
}

void rem_breakpoint_event_listener(BreakpointsEventListener * listener) {
    unsigned i = 0;
    while (i < listener_cnt) {
        if (listeners[i++].listener == listener) {
            while (i < listener_cnt) {
                listeners[i - 1] = listeners[i];
                i++;
            }
            listener_cnt--;
            break;
        }
    }
}

void iterate_breakpoints(IterateBreakpointsCallBack * callback, void * args) {
    LINK * l = breakpoints.next;
    while (l != &breakpoints) {
        BreakpointInfo * bp = link_all2bp(l);
        l = l->next;
        callback(bp, args);
    }
}

BreakpointAttribute * get_breakpoint_attributes(BreakpointInfo * bp) {
    return bp->attrs;
}

BreakpointInfo * create_breakpoint(BreakpointAttribute * attrs) {
    return add_breakpoint(NULL, attrs);
}

void change_breakpoint_attributes(BreakpointInfo * bp, BreakpointAttribute * attrs) {
    int chng = set_breakpoint_attributes(bp, attrs);
    assert(!list_is_empty(&bp->link_clients));
    if (chng) {
        bp->attrs_changed = 1;
        replant_breakpoint(bp);
        send_event_context_changed(bp);
    }
}

void delete_breakpoint(BreakpointInfo * bp) {
    BreakpointRef * br = find_breakpoint_ref(bp, NULL);
    assert(br != NULL && br->channel == NULL);
    remove_ref(br);
}

void iterate_context_breakpoint_links(Context * ctx, ContextBreakpoint * cb, IterateCBLinksCallBack * callback, void * args) {
    int i;
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT);
    BreakInstruction * bi = (BreakInstruction *)((char *)cb - offsetof(BreakInstruction, cb));
    for (i = 0; i < bi->ref_cnt; i++) {
        if (bi->refs[i].ctx == grp) callback(bi->refs[i].bp, args);
    }
}

int is_breakpoint_address(Context * ctx, ContextAddress address) {
    Context * mem = NULL;
    ContextAddress mem_addr = 0;
    BreakInstruction * bi = NULL;
    if (context_get_canonical_addr(ctx, address, &mem, &mem_addr, NULL, NULL) < 0) return 0;
    bi = find_instruction(mem, 0, mem_addr, CTX_BP_ACCESS_INSTRUCTION, 1);
    return bi != NULL && bi->planted;
}

void evaluate_breakpoint(Context * ctx) {
    int i;
    Context * mem = NULL;
    ContextAddress mem_addr = 0;
    BreakInstruction * bi = NULL;
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT);
    EvaluationRequest * req = create_evaluation_request(grp);
    int need_to_post = !list_is_empty(&req->link_posted);

    assert(context_has_state(ctx));
    assert(ctx->stopped);
    assert(ctx->stopped_by_bp || ctx->stopped_by_cb);
    assert(ctx->exited == 0);
    assert(EXT(ctx)->bp_ids == NULL);
    assert(list_is_empty(&req->link_active));

    if (ctx->stopped_by_bp) {
        if (context_get_canonical_addr(ctx, get_regs_PC(ctx), &mem, &mem_addr, NULL, NULL) < 0) return;
        bi = find_instruction(mem, 0, mem_addr, CTX_BP_ACCESS_INSTRUCTION, 1);
        if (bi != NULL && bi->planted) {
            assert(bi->valid);
            for (i = 0; i < bi->ref_cnt; i++) {
                if (bi->refs[i].ctx == grp) {
                    BreakpointInfo * bp = bi->refs[i].bp;
                    ConditionEvaluationRequest * c = add_condition_evaluation_request(req, ctx, bp);
                    if (c == NULL) continue;
                    if (need_to_post) continue;
                    if (is_disabled(bp)) continue;
                    if (bp->condition != NULL || bp->stop_group != NULL || bp->temporary) {
                        need_to_post = 1;
                        continue;
                    }
                    if (!check_context_ids_condition(bp, ctx)) continue;
                    c->condition_ok = 1;
                }
            }
        }
    }
    if (ctx->stopped_by_cb) {
        int j;
        assert(ctx->stopped_by_cb[0] != NULL);
        for (j = 0; ctx->stopped_by_cb[j]; j++) {
            bi = (BreakInstruction *)((char *)ctx->stopped_by_cb[j] - offsetof(BreakInstruction, cb));
            assert(bi->planted);
            for (i = 0; i < bi->ref_cnt; i++) {
                if (bi->refs[i].ctx == grp) {
                    BreakpointInfo * bp = bi->refs[i].bp;
                    ConditionEvaluationRequest * c = add_condition_evaluation_request(req, ctx, bp);
                    if (c == NULL) continue;
                    if (need_to_post) continue;
                    if (is_disabled(bp)) continue;
                    if (bp->condition != NULL || bp->stop_group != NULL || bp->temporary) {
                        need_to_post = 1;
                        continue;
                    }
                    if (!check_context_ids_condition(bp, ctx)) continue;
                    c->condition_ok = 1;
                }
            }
        }
    }

    if (need_to_post) {
        post_evaluation_request(req);
    }
    else {
        done_condition_evaluation(req);
        for (i = 0; i < req->bp_cnt; i++) {
            ConditionEvaluationRequest * c = req->bp_arr + i;
            if (c->bp->status_changed && generation_done == generation_posted) {
                assert(c->bp->client_cnt > 0);
                notify_breakpoint_status(c->bp);
            }
            context_unlock(c->ctx);
        }
        req->bp_cnt = 0;
    }
}

char ** get_context_breakpoint_ids(Context * ctx) {
    return EXT(ctx)->bp_ids;
}

static void safe_skip_breakpoint(void * arg);

static void safe_restore_breakpoint(void * arg) {
    Context * ctx = (Context *)arg;
    ContextExtensionBP * ext = EXT(ctx);
    BreakInstruction * bi = ext->stepping_over_bp;

    assert(bi->stepping_over_bp > 0);
    assert(find_instruction(bi->cb.ctx, 0, bi->cb.address, bi->cb.access_types, bi->cb.length) == bi);
    if (!ctx->exiting && ctx->stopped && !ctx->stopped_by_exception && get_regs_PC(ctx) == bi->cb.address) {
        if (ext->step_over_bp_cnt < 100) {
            ext->step_over_bp_cnt++;
            safe_skip_breakpoint(arg);
            return;
        }
        trace(LOG_ALWAYS, "Skip breakpoint error: wrong PC %#lx", get_regs_PC(ctx));
    }
    ext->stepping_over_bp = NULL;
    ext->step_over_bp_cnt = 0;
    bi->stepping_over_bp--;
    if (bi->stepping_over_bp == 0) {
        if (generation_done != generation_posted) {
            bi->valid = 0;
        }
        else if (!ctx->exited && !ctx->exiting && bi->ref_cnt > 0 && !bi->planted) {
            plant_instruction(bi);
        }
    }
    context_unlock(ctx);
}

static void safe_skip_breakpoint(void * arg) {
    Context * ctx = (Context *)arg;
    ContextExtensionBP * ext = EXT(ctx);
    BreakInstruction * bi = ext->stepping_over_bp;
    int error = 0;

    assert(bi != NULL);
    assert(bi->stepping_over_bp > 0);
    assert(find_instruction(bi->cb.ctx, 0, bi->cb.address, bi->cb.access_types, bi->cb.length) == bi);

    post_safe_event(ctx, safe_restore_breakpoint, ctx);

    if (ctx->exited || ctx->exiting) return;

    assert(ctx->stopped);
    assert(!is_intercepted(ctx));
    assert(bi->cb.address == get_regs_PC(ctx));

    if (bi->planted) remove_instruction(bi);
    if (bi->planting_error) error = set_error_report_errno(bi->planting_error);
    if (error == 0 && safe_context_single_step(ctx) < 0) error = errno;
    if (error) {
        error = set_errno(error, "Cannot step over breakpoint");
        ctx->signal = 0;
        ctx->stopped = 1;
        ctx->stopped_by_bp = 0;
        ctx->stopped_by_cb = NULL;
        ctx->stopped_by_exception = 1;
        ctx->pending_intercept = 1;
        loc_free(ctx->exception_description);
        ctx->exception_description = loc_strdup(errno_to_str(error));
        send_context_changed_event(ctx);
    }
}

/*
 * When a context is stopped by breakpoint, it is necessary to disable
 * the breakpoint temporarily before the context can be resumed.
 * This function function removes break instruction, then does single step
 * over breakpoint location, then restores break intruction.
 * Return: 0 if it is OK to resume context from current state,
 * return 1 if context needs to step over a breakpoint.
 */
int skip_breakpoint(Context * ctx, int single_step) {
    ContextExtensionBP * ext = EXT(ctx);
    Context * mem = NULL;
    ContextAddress mem_addr = 0;
    BreakInstruction * bi;

    assert(ctx->stopped);
    assert(!ctx->exited);
    assert(single_step || ext->stepping_over_bp == NULL);

    if (ext->stepping_over_bp != NULL) return 0;
    if (!ctx->stopped_by_bp && ctx->stopped_by_cb == NULL) return 0;
    if (ctx->exited || ctx->exiting) return 0;

    if (context_get_canonical_addr(ctx, get_regs_PC(ctx), &mem, &mem_addr, NULL, NULL) < 0) return -1;
    bi = find_instruction(mem, 0, mem_addr, CTX_BP_ACCESS_INSTRUCTION, 1);
    if (bi == NULL || bi->planting_error) return 0;
    bi->stepping_over_bp++;
    ext->stepping_over_bp = bi;
    ext->step_over_bp_cnt = 1;
    assert(bi->stepping_over_bp > 0);
    context_lock(ctx);
    post_safe_event(ctx, safe_skip_breakpoint, ctx);
    return 1;
}

BreakpointInfo * create_eventpoint(const char * location, Context * ctx, EventPointCallBack * callback, void * callback_args) {
    static const char * attr_list[] = { BREAKPOINT_ENABLED, BREAKPOINT_LOCATION };
    BreakpointInfo * bp = (BreakpointInfo *)loc_alloc_zero(sizeof(BreakpointInfo));
    BreakpointAttribute ** ref = &bp->attrs;
    unsigned i;

    bp->client_cnt = 1;
    bp->enabled = 1;
    if (location != NULL) bp->location = loc_strdup(location);
    if (ctx != NULL) context_lock(bp->ctx = ctx);

    /* Create attributes to allow get_breakpoint_attributes() and change_breakpoint_attributes() calls */
    for (i = 0; i < sizeof(attr_list) / sizeof(char *); i++) {
        ByteArrayOutputStream buf;
        BreakpointAttribute * attr = (BreakpointAttribute *)loc_alloc_zero(sizeof(BreakpointAttribute));
        OutputStream * out = create_byte_array_output_stream(&buf);
        attr->name = loc_strdup(attr_list[i]);
        switch (i) {
        case 0:
            json_write_boolean(out, bp->enabled);
            break;
        case 1:
            json_write_string(out, bp->location);
            break;
        }
        write_stream(out, 0);
        get_byte_array_output_stream_data(&buf, &attr->value, NULL);
        *ref = attr; ref = &attr->next;
    }

    bp->event_callback = callback;
    bp->event_callback_args = callback_args;
    list_init(&bp->link_clients);
    list_init(&bp->link_hit_count);
    assert(breakpoints.next != NULL);
    list_add_last(&bp->link_all, &breakpoints);
    replant_breakpoint(bp);
    return bp;
}

void destroy_eventpoint(BreakpointInfo * bp) {
    assert(bp->id[0] == 0);
    assert(bp->client_cnt == 1);
    assert(list_is_empty(&bp->link_clients));
    bp->client_cnt = 0;
    replant_breakpoint(bp);
}

static void event_context_created(Context * ctx, void * args) {
    post_location_evaluation_request(ctx, NULL);
    list_init(&EXT(ctx)->link_hit_count);
}

static void event_context_changed(Context * ctx, void * args) {
    if (ctx->mem_access && context_get_group(ctx, CONTEXT_GROUP_PROCESS) == ctx) {
        /* If the context is a memory space, we need to update
         * breakpoints on all members of the group */
        LINK * l = context_root.next;
        while (l != &context_root) {
            Context * x = ctxl2ctxp(l);
            l = l->next;
            if (x->exited) continue;
            if (context_get_group(x, CONTEXT_GROUP_PROCESS) != ctx) continue;
            post_location_evaluation_request(x, NULL);
        }
    }
    else {
        post_location_evaluation_request(ctx, NULL);
    }
}

static void event_context_started(Context * ctx, void * args) {
    ContextExtensionBP * ext = EXT(ctx);
    if (ext->bp_ids != NULL) {
        loc_free(ext->bp_ids);
        ext->bp_ids = NULL;
    }
}

static void event_context_exited(Context * ctx, void * args) {
    post_location_evaluation_request(ctx, NULL);
}

static void event_context_disposed(Context * ctx, void * args) {
    LINK * l = NULL;
    ContextExtensionBP * ext = EXT(ctx);
    EvaluationRequest * req = ext->req;
    if (req != NULL) {
        int i;
        for (i = 0; i < req->bp_cnt; i++) context_unlock(req->bp_arr[i].ctx);
        req->bp_cnt = 0;
        loc_free(req->bp_arr);
        loc_free(req);
        ext->req = NULL;
    }
    if (ext->bp_ids != NULL) {
        loc_free(ext->bp_ids);
        ext->bp_ids = NULL;
    }
    l = ext->link_hit_count.next;
    while (l != &ext->link_hit_count) {
        BreakpointHitCount * c = link_ctx2hcnt(l);
        l = l->next;
        list_remove(&c->link_bp);
        list_remove(&c->link_ctx);
        loc_free(c);
    }
}

#if SERVICE_MemoryMap
static void event_code_unmapped(Context * ctx, ContextAddress addr, ContextAddress size, void * args) {
    /* Unmapping a code section unplants all breakpoint instructions in that section as side effect.
     * This function udates service data structure to reflect that.
     */
    int cnt = 0;
    while (size > 0) {
        ContextAddress sz = size;
        LINK * l = instructions.next;
        Context * mem = NULL;
        ContextAddress mem_addr = 0;
        ContextAddress mem_base = 0;
        ContextAddress mem_size = 0;
        if (context_get_canonical_addr(ctx, addr, &mem, &mem_addr, &mem_base, &mem_size) < 0) break;
        if (mem_base + mem_size - mem_addr < sz) sz = mem_base + mem_size - mem_addr;
        while (l != &instructions) {
            int i;
            BreakInstruction * bi = link_all2bi(l);
            l = l->next;
            if (bi->cb.ctx != mem) continue;
            if (!bi->planted) continue;
            if (bi->cb.address < mem_addr || bi->cb.address >= mem_addr + sz) continue;
            for (i = 0; i < bi->ref_cnt; i++) {
                bi->refs[i].bp->status_changed = 1;
                cnt++;
            }
            bi->planted = 0;
        }
        addr += sz;
        size -= sz;
    }
    if (cnt > 0 && generation_done == generation_posted) done_replanting_breakpoints();
}
#endif

#if SERVICE_PathMap
static void event_path_map_changed(Channel * c, void * args) {
    unsigned hash = (unsigned)(uintptr_t)c / 16 % INP2BR_HASH_SIZE;
    LINK * l = inp2br[hash].next;
    while (l != &inp2br[hash]) {
        BreakpointRef * br = link_inp2br(l);
        l = l->next;
        if (br->channel == c && br->bp->file != NULL) replant_breakpoint(br->bp);
    }
}
#endif

static void channel_close_listener(Channel * c) {
    delete_breakpoint_refs(c);
}

void ini_breakpoints_service(Protocol * proto, TCFBroadcastGroup * bcg) {
    int i;
    broadcast_group = bcg;

    {
        static ContextEventListener listener = {
            event_context_created,
            event_context_exited,
            NULL,
            event_context_started,
            event_context_changed,
            event_context_disposed
        };
        add_context_event_listener(&listener, NULL);
    }
#if SERVICE_MemoryMap
    {
        static MemoryMapEventListener listener = {
            event_context_changed,
            event_code_unmapped,
            event_context_changed,
            event_context_changed,
        };
        add_memory_map_event_listener(&listener, NULL);
    }
#endif
#if SERVICE_PathMap
    {
        static PathMapEventListener listener = {
            event_path_map_changed,
        };
        add_path_map_event_listener(&listener, NULL);
    }
#endif
    for (i = 0; i < ADDR2INSTR_HASH_SIZE; i++) list_init(addr2instr + i);
    for (i = 0; i < ID2BP_HASH_SIZE; i++) list_init(id2bp + i);
    for (i = 0; i < INP2BR_HASH_SIZE; i++) list_init(inp2br + i);
    add_channel_close_listener(channel_close_listener);
    add_command_handler(proto, BREAKPOINTS, "set", command_set);
    add_command_handler(proto, BREAKPOINTS, "add", command_add);
    add_command_handler(proto, BREAKPOINTS, "change", command_change);
    add_command_handler(proto, BREAKPOINTS, "enable", command_enable);
    add_command_handler(proto, BREAKPOINTS, "disable", command_disable);
    add_command_handler(proto, BREAKPOINTS, "remove", command_remove);
    add_command_handler(proto, BREAKPOINTS, "getIDs", command_get_ids);
    add_command_handler(proto, BREAKPOINTS, "getProperties", command_get_properties);
    add_command_handler(proto, BREAKPOINTS, "getStatus", command_get_status);
    add_command_handler(proto, BREAKPOINTS, "getCapabilities", command_get_capabilities);
    context_extension_offset = context_extension(sizeof(ContextExtensionBP));
}

#endif /* SERVICE_Breakpoints */
