/*******************************************************************************
 * Copyright (c) 2013 Stanislav Yakovlev and others.
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
 *     Stanislav Yakovlev - initial API and implementation
 * Emmanuel Touron (Wind River) - initial ARM stepping emulation
 *******************************************************************************/

#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/symbols.h>
#include <machine/arm/tcf/disassembler-arm.h>
#include <machine/arm/tcf/stack-crawl-arm.h>
#include <tcf/cpudefs-mdep.h>

#define REG_OFFSET(name) offsetof(REG_SET, name)

RegisterDefinition regs_def[] = {
#   define REG_FP user.regs.uregs[11]
#   define REG_SP user.regs.uregs[13]
#   define REG_PC user.regs.uregs[15]
#   define REG_CPSR user.regs.uregs[16]
    { "r0",      REG_OFFSET(user.regs.uregs[0]),      4, 0, 0},
    { "r1",      REG_OFFSET(user.regs.uregs[1]),      4, 1, 1},
    { "r2",      REG_OFFSET(user.regs.uregs[2]),      4, 2, 2},
    { "r3",      REG_OFFSET(user.regs.uregs[3]),      4, 3, 3},
    { "r4",      REG_OFFSET(user.regs.uregs[4]),      4, 4, 4},
    { "r5",      REG_OFFSET(user.regs.uregs[5]),      4, 5, 5},
    { "r6",      REG_OFFSET(user.regs.uregs[6]),      4, 6, 6},
    { "r7",      REG_OFFSET(user.regs.uregs[7]),      4, 7, 7},
    { "r8",      REG_OFFSET(user.regs.uregs[8]),      4, 8, 8},
    { "r9",      REG_OFFSET(user.regs.uregs[9]),      4, 9, 9},
    { "r10",     REG_OFFSET(user.regs.uregs[10]),     4, 10, 10},
    { "fp",      REG_OFFSET(user.regs.uregs[11]),     4, 11, 11},
    { "ip",      REG_OFFSET(user.regs.uregs[12]),     4, 12, 12},
    { "sp",      REG_OFFSET(user.regs.uregs[13]),     4, 13, 13},
    { "lr",      REG_OFFSET(user.regs.uregs[14]),     4, 14, 14},
    { "pc",      REG_OFFSET(user.regs.uregs[15]),     4, 15, 15},
    { "cpsr",    REG_OFFSET(user.regs.uregs[16]),     4, -1, -1},
    { "orig_r0", REG_OFFSET(user.regs.uregs[17]),     4, -1, -1},
    { "debug",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 18 */
    { "bp_info", REG_OFFSET(other.bp_info),           4, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, regs_def + 18},
    { "bvr0",    REG_OFFSET(other.bp[0].vr),     4, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, regs_def + 18},
    { "bcr0",    REG_OFFSET(other.bp[0].cr),     4, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, regs_def + 18},
    { NULL,     0,                    0,  0,  0},
};

RegisterDefinition * regs_index = NULL;

unsigned char BREAK_INST[] = { 0x7f, 0xff, 0x2f, 0xe1 };

static RegisterDefinition * pc_def = NULL;
static RegisterDefinition * cpsr_def = NULL;

#ifdef MDEP_OtherRegisters

#include <sys/ptrace.h>

#if !defined(PTRACE_GETHBPREGS)
#define PTRACE_GETHBPREGS 29
#endif
#if !defined(PTRACE_SETHBPREGS)
#define PTRACE_SETHBPREGS 30
#endif
#define MAX_HWP 1
static int offset_to_regnum(size_t offset) {
    int bp_id = (offset - 4) >> 3;
    int reg_offset = 1 + (((offset - 4) >> 2) & 1);
    if (offset == 0) return 0;
    trace (LOG_ALWAYS,"offset_to_regnum offset %x, bp_id %x, reg_offset %x", offset, bp_id, reg_offset);
    if (bp_id >= MAX_HWP) return - (((bp_id - MAX_HWP) << 1) + reg_offset);
    return (bp_id << 1) + reg_offset;
}

int mdep_get_other_regs(pid_t pid, REG_SET * data,
                       size_t data_offs, size_t data_size,
                       size_t * done_offs, size_t * done_size) {
    size_t size = 0;
    assert(data_offs >= offsetof(REG_SET, other));
    assert(data_offs + data_size <= offsetof(REG_SET, other) + sizeof(data->other));
    /* bp registers can only be accessed 1 at a time */
    for (size = data_offs - offsetof(REG_SET, other); size < sizeof(data->other); size += 4) {
        trace (LOG_ALWAYS,"get_other_registers %x", offset_to_regnum(size));
        if (ptrace(PTRACE_GETHBPREGS, pid, offset_to_regnum (size), (char *)&data->other + size) < 0) return -1;
    }
    *done_offs = offsetof(REG_SET, other);
    *done_size = sizeof(data->other);
    return 0;
}

int mdep_set_other_regs(pid_t pid, REG_SET * data,
                       size_t data_offs, size_t data_size,
                       size_t * done_offs, size_t * done_size) {
    size_t size = 0;
    assert(data_offs >= offsetof(REG_SET, other));
    assert(data_offs + data_size <= offsetof(REG_SET, other) + sizeof(data->other));
    /* bp registers can only be accessed 1 at a time */
    for (size = data_offs - offsetof(REG_SET, other); size < data_offs + data_size - offsetof(REG_SET, other); size += 4) {
        trace (LOG_ALWAYS,"set_other_registers %x", offset_to_regnum(size));
        if (ptrace(PTRACE_SETHBPREGS, pid, offset_to_regnum(size), (char *)&data->other + size) < 0) return -1;
    }
    *done_offs = offsetof(REG_SET, other);
    *done_size = sizeof(data->other);
    return 0;
}

#endif

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return pc_def;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return crawl_stack_frame_arm(frame, down);
}

void add_cpudefs_disassembler(Context * cpu_ctx) {
    add_disassembler(cpu_ctx, "ARM", disassemble_arm);
    add_disassembler(cpu_ctx, "Thumb", disassemble_thumb);
}

static int read_reg(Context *ctx, RegisterDefinition * def, size_t size, ContextAddress * addr) {
    size_t i;
    uint8_t buf[8];
    uint64_t n = 0;
    *addr = 0;
    assert(!def->big_endian);
    assert(size <= def->size);
    assert(size <= sizeof(buf));
    if (context_read_reg(ctx, def, 0, size, buf) < 0) return -1;
    for (i = 0; i < size; i++) n |= (uint64_t)buf[i] << (i * 8);
    *addr = (ContextAddress)n;
    return 0;
}

typedef struct ContextExtensionARM {
    char opcode[sizeof(BREAK_INST)];
    ContextAddress addr;
    int stepping;
} ContextExtensionARM;

static size_t context_extension_offset = 0;

#define EXT(ctx) ((ContextExtensionARM *)((char *)(ctx) + context_extension_offset))

#define GET_GROUP(a) (((a) >> 25) & 7)
#define BRANCH_LINK 5

static int arm_evaluate_condition (uint32_t opc, uint32_t cpsr) {
    int N = ( cpsr >> 31 ) & 1;
    int Z = ( cpsr >> 30 ) & 1;
    int C = ( cpsr >> 29 ) & 1;
    int V = ( cpsr >> 28 ) & 1;

    switch (opc >> 28) {
    case 0 : return Z;
    case 1 : return Z == 0;
    case 2 : return C;
    case 3 : return C == 0;
    case 4 : return N;
    case 5 : return N == 0;
    case 6 : return V;
    case 7 : return V == 0;
    case 8 : return C == 0 && Z == 0;
    case 9 : return C == 0 || Z == 1;
    case 10: return N == V;
    case 11: return N != V;
    case 12: return Z == 0 && N == V;
    case 13: return Z == 1 || N != V;
    }

    return 1;
}

static ContextAddress arm_get_next_branch (Context * ctx, ContextAddress addr, uint32_t opc, int cond) {
    int32_t imm = opc & 0x00FFFFFF;
    if (cond == 0) return addr + 4;
    if (imm & 0x00800000) imm |= 0xFF000000;
    imm = imm << 2;
    return (ContextAddress)((int)addr + imm + 8);
}

static ContextAddress arm_get_next_address (Context * ctx) {
    ContextAddress addr;
    uint32_t opc;
    ContextAddress cpsr;
    int cond;

    /* read opcode at PC */
    if (read_reg(ctx, pc_def, pc_def->size, &addr) < 0) return -1;
    if (read_reg(ctx, cpsr_def, cpsr_def->size, &cpsr) < 0) return -1;
    if (context_read_mem(ctx, addr, &opc, sizeof(opc)) < 0) return -1;
    trace (LOG_ALWAYS, "pc: 0x%x, opcode 0x%x", (int)addr, (int)opc);

    /* decode opcode */
    cond = arm_evaluate_condition (opc, (uint32_t) cpsr);

    switch (GET_GROUP(opc)) {
//    case LD_ST_IMM : return get_next_load_store_imm ();
    case BRANCH_LINK : return arm_get_next_branch (ctx, addr, opc, cond);
    }
    return addr + 4;
}

int cpu_enable_stepping_mode (Context * ctx, uint32_t * is_cont) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionARM * ext = EXT(grp);
    assert (!ext->stepping);
    ext->addr = arm_get_next_address (ctx);
    trace (LOG_ALWAYS, "cpu_enable_stepping_mode 0x%x", (int) ext->addr);
    if (context_read_mem(ctx, ext->addr, ext->opcode, sizeof(BREAK_INST)) < 0) return -1;
    if (context_write_mem(ctx,ext->addr, BREAK_INST, sizeof(BREAK_INST)) < 0) return -1;
    ext->stepping = 1;
    *is_cont = 1;
    return 0;
}

int cpu_disable_stepping_mode (Context * ctx) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionARM * ext = EXT(grp);
    trace (LOG_ALWAYS, "cpu_disable_stepping_mode");
    if (ext->stepping) {
        ext->stepping = 0;
        return context_write_mem(ctx, ext->addr, ext->opcode, sizeof(BREAK_INST));
    }
    return 0;
}

void ini_cpudefs_mdep(void) {
    RegisterDefinition * r;
    for (r = regs_def; r->name != NULL; r++) {
        if (r->offset == offsetof(REG_SET, REG_FP)) {
            r->role = "FP";
        }
        else if (r->offset == offsetof(REG_SET, REG_SP)) {
            r->role = "SP";
        }
        else if (r->offset == offsetof(REG_SET, REG_PC)) {
            r->role = "PC";
            pc_def = r;
        }
        else if (r->offset == offsetof(REG_SET, REG_CPSR)) {
            cpsr_def = r;
        }
    }
    regs_index = regs_def;
    context_extension_offset = context_extension(sizeof(ContextExtensionARM));
}

#endif
