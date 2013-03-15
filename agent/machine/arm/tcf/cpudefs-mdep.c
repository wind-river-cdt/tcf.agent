/*******************************************************************************
 * Copyright (c) 2013 Stanislav Yakovlev.
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
#include <tcf/services/symbols.h>
#include <tcf/cpudefs-mdep.h>

#if defined(__arm__)

#define REG_OFFSET(name) offsetof(REG_SET, name)

RegisterDefinition regs_def[] = {
#   define REG_FP user.regs.uregs[11]
#   define REG_SP user.regs.uregs[13]
#   define REG_PC user.regs.uregs[15]
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
    { NULL,     0,                    0,  0,  0},
};

RegisterDefinition * regs_index = NULL;

unsigned char BREAK_INST[] = { 0xf0, 0x01, 0xf0, 0xe7 };

static RegisterDefinition * fp_def = NULL;
static RegisterDefinition * sp_def = NULL;
static RegisterDefinition * pc_def = NULL;

void ini_cpudefs_mdep(void) {
    RegisterDefinition * r;
    for (r = regs_def; r->name != NULL; r++) {
        if (r->offset == offsetof(REG_SET, REG_FP)) fp_def = r;
        if (r->offset == offsetof(REG_SET, REG_SP)) sp_def = r;
        if (r->offset == offsetof(REG_SET, REG_PC)) pc_def = r;
    }
    regs_index = regs_def;
}

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return pc_def;
}

static int read_reg(StackFrame * frame, RegisterDefinition * def, ContextAddress * addr) {
    uint8_t buf[4];
    uint32_t val;
    assert(sizeof(buf) == def->size);
    *addr = 0;
    if (read_reg_bytes(frame, def, 0, def->size, buf) < 0) return -1;
    val = buf[3];
    val <<= 8;
    val += buf[2];
    val <<= 8;
    val += buf[1];
    val <<= 8;
    val += buf[0];
    *addr = (ContextAddress)val;
    return 0;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down)
{
    size_t word_size = 4;
    ContextAddress fp = 0;
    ContextAddress down_fp = 0;
    ContextAddress down_sp = 0;
    ContextAddress down_pc = 0;
    Context * ctx = frame->ctx;
    if (read_reg(frame, fp_def, &fp) < 0) return 0;
    if (context_read_mem(ctx, fp - word_size*1, &down_pc, word_size) < 0) down_pc = 0;
    if (context_read_mem(ctx, fp - word_size*2, &down_sp, word_size) < 0) down_sp = 0;
    if (context_read_mem(ctx, fp - word_size*3, &down_fp, word_size) < 0) down_fp = 0;
    if (down_fp != 0 && write_reg_value(down, fp_def, down_fp) < 0) return -1;
    if (down_sp != 0 && write_reg_value(down, sp_def, down_sp) < 0) return -1;
    if (down_pc != 0 && write_reg_value(down, pc_def, down_pc) < 0) return -1;
    return 0;
}

#endif
#endif
