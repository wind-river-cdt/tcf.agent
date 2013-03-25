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
#include <machine/arm/tcf/disassembler-arm.h>
#include <machine/arm/tcf/stack-crawl-arm.h>
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

static RegisterDefinition * pc_def = NULL;

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
    }
    regs_index = regs_def;
}

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

#endif
#endif
