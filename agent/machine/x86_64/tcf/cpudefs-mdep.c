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

#if defined(__i386__) || defined(__x86_64__)

#if defined(__x86_64__)
#  define XMM_REGS 16
#else
#  define XMM_REGS 8
#endif
#define XMM_SIZE 128

#define REG_OFFSET(name) offsetof(REG_SET, name)

#define regs_index regs_def

RegisterDefinition regs_def[] = {
#if defined(_WIN32) && defined(__i386__)
#   define REG_SP Esp
#   define REG_BP Ebp
#   define REG_IP Eip
    { "eax",    REG_OFFSET(Eax),      4,  0,  0 },
    { "ebx",    REG_OFFSET(Ebx),      4,  3,  3 },
    { "ecx",    REG_OFFSET(Ecx),      4,  1,  1 },
    { "edx",    REG_OFFSET(Edx),      4,  2,  2 },
    { "esp",    REG_OFFSET(Esp),      4,  4,  4 },
    { "ebp",    REG_OFFSET(Ebp),      4,  5,  5 },
    { "esi",    REG_OFFSET(Esi),      4,  6,  6 },
    { "edi",    REG_OFFSET(Edi),      4,  7,  7 },
    { "eip",    REG_OFFSET(Eip),      4,  8,  8 },
    { "eflags", REG_OFFSET(EFlags),   4,  9,  9 },
    { "cs",     REG_OFFSET(SegCs),    2, -1, -1 },
    { "ss",     REG_OFFSET(SegSs),    2, -1, -1 },

    { "ax",     REG_OFFSET(Eax),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 0 },
    { "al",     REG_OFFSET(Eax),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 12 },
    { "ah",     REG_OFFSET(Eax) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 12 },

    { "bx",     REG_OFFSET(Ebx),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 1 },
    { "bl",     REG_OFFSET(Ebx),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 15 },
    { "bh",     REG_OFFSET(Ebx) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 15 },

    { "cx",     REG_OFFSET(Ecx),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 2 },
    { "cl",     REG_OFFSET(Ecx),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 18 },
    { "ch",     REG_OFFSET(Ecx) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 18 },

    { "dx",     REG_OFFSET(Edx),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 3 },
    { "dl",     REG_OFFSET(Edx),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 21 },
    { "dh",     REG_OFFSET(Edx) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 21 },

    { "fpu",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 24 */

    { "f0", REG_OFFSET(FloatSave.RegisterArea) + 0,  10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f1", REG_OFFSET(FloatSave.RegisterArea) + 10, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f2", REG_OFFSET(FloatSave.RegisterArea) + 20, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f3", REG_OFFSET(FloatSave.RegisterArea) + 30, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f4", REG_OFFSET(FloatSave.RegisterArea) + 40, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f5", REG_OFFSET(FloatSave.RegisterArea) + 50, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f6", REG_OFFSET(FloatSave.RegisterArea) + 60, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f7", REG_OFFSET(FloatSave.RegisterArea) + 70, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },

    { "control", REG_OFFSET(FloatSave.ControlWord),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "status",  REG_OFFSET(FloatSave.StatusWord),   2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "tag",     REG_OFFSET(FloatSave.TagWord),      1, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },

    { "debug",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 36 */

    { "dr0",    REG_OFFSET(Dr0), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr1",    REG_OFFSET(Dr1), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr2",    REG_OFFSET(Dr2), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr3",    REG_OFFSET(Dr3), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr6",    REG_OFFSET(Dr6), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr7",    REG_OFFSET(Dr7), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },

#elif defined(_WIN32) && defined(__x86_64__)
#   define REG_SP Rsp
#   define REG_BP Rbp
#   define REG_IP Rip
    { "rax",    REG_OFFSET(Rax),      8,  0,  0},
    { "rdx",    REG_OFFSET(Rdx),      8,  1,  1},
    { "rcx",    REG_OFFSET(Rcx),      8,  2,  2},
    { "rbx",    REG_OFFSET(Rbx),      8,  3,  3},
    { "rsi",    REG_OFFSET(Rsi),      8,  4,  4},
    { "rdi",    REG_OFFSET(Rdi),      8,  5,  5},
    { "rbp",    REG_OFFSET(Rbp),      8,  6,  6},
    { "rsp",    REG_OFFSET(Rsp),      8,  7,  7},
    { "r8",     REG_OFFSET(R8),       8,  8,  8},
    { "r9",     REG_OFFSET(R9),       8,  9,  9},
    { "r10",    REG_OFFSET(R10),      8, 10, 10},
    { "r11",    REG_OFFSET(R11),      8, 11, 11},
    { "r12",    REG_OFFSET(R12),      8, 12, 12},
    { "r13",    REG_OFFSET(R13),      8, 13, 13},
    { "r14",    REG_OFFSET(R14),      8, 14, 14},
    { "r15",    REG_OFFSET(R15),      8, 15, 15},
    { "rip",    REG_OFFSET(Rip),      8, 16, 16},
    { "eflags", REG_OFFSET(EFlags),   4, 49, -1},
    { "es",     REG_OFFSET(SegEs),    2, 50, -1},
    { "cs",     REG_OFFSET(SegCs),    2, 51, -1},
    { "ss",     REG_OFFSET(SegSs),    2, 52, -1},
    { "ds",     REG_OFFSET(SegDs),    2, 53, -1},
    { "fs",     REG_OFFSET(SegFs),    2, 54, -1},
    { "gs",     REG_OFFSET(SegGs),    2, 55, -1},

    { "fpu",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 24 */

    { "f0", REG_OFFSET(FltSave.FloatRegisters[0]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f1", REG_OFFSET(FltSave.FloatRegisters[1]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f2", REG_OFFSET(FltSave.FloatRegisters[2]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f3", REG_OFFSET(FltSave.FloatRegisters[3]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f4", REG_OFFSET(FltSave.FloatRegisters[4]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f5", REG_OFFSET(FltSave.FloatRegisters[5]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f6", REG_OFFSET(FltSave.FloatRegisters[6]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "f7", REG_OFFSET(FltSave.FloatRegisters[7]), 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },

    { "control", REG_OFFSET(FltSave.ControlWord),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "status",  REG_OFFSET(FltSave.StatusWord),   2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },
    { "tag",     REG_OFFSET(FltSave.TagWord),      1, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 24 },

    { "debug",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 36 */

    { "dr0",    REG_OFFSET(Dr0), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr1",    REG_OFFSET(Dr1), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr2",    REG_OFFSET(Dr2), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr3",    REG_OFFSET(Dr3), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr6",    REG_OFFSET(Dr6), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },
    { "dr7",    REG_OFFSET(Dr7), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 36 },

#elif defined(__APPLE__) && defined(__i386__)
#   define REG_SP __esp
#   define REG_BP __ebp
#   define REG_IP __eip
    { "eax",    REG_OFFSET(__eax),    4,  0,  0},
    { "ecx",    REG_OFFSET(__ecx),    4,  1,  1},
    { "edx",    REG_OFFSET(__edx),    4,  2,  2},
    { "ebx",    REG_OFFSET(__ebx),    4,  3,  3},
    { "esp",    REG_OFFSET(__esp),    4,  4,  4},
    { "ebp",    REG_OFFSET(__ebp),    4,  5,  5},
    { "esi",    REG_OFFSET(__esi),    4,  6,  6},
    { "edi",    REG_OFFSET(__edi),    4,  7,  7},
    { "eip",    REG_OFFSET(__eip),    4,  8,  8},
    { "eflags", REG_OFFSET(__eflags), 4,  9,  9},

#elif defined(__APPLE__) && defined(__x86_64__)
#   define REG_SP __rsp
#   define REG_BP __rbp
#   define REG_IP __rip
    { "rax",    REG_OFFSET(__rax),    8,  0,  0},
    { "rdx",    REG_OFFSET(__rdx),    8,  1,  1},
    { "rcx",    REG_OFFSET(__rcx),    8,  2,  2},
    { "rbx",    REG_OFFSET(__rbx),    8,  3,  3},
    { "rsi",    REG_OFFSET(__rsi),    8,  4,  4},
    { "rdi",    REG_OFFSET(__rdi),    8,  5,  5},
    { "rbp",    REG_OFFSET(__rbp),    8,  6,  6},
    { "rsp",    REG_OFFSET(__rsp),    8,  7,  7},
    { "r8",     REG_OFFSET(__r8),     8,  8,  8},
    { "r9",     REG_OFFSET(__r9),     8,  9,  9},
    { "r10",    REG_OFFSET(__r10),    8, 10, 10},
    { "r11",    REG_OFFSET(__r11),    8, 11, 11},
    { "r12",    REG_OFFSET(__r12),    8, 12, 12},
    { "r13",    REG_OFFSET(__r13),    8, 13, 13},
    { "r14",    REG_OFFSET(__r14),    8, 14, 14},
    { "r15",    REG_OFFSET(__r15),    8, 15, 15},
    { "rip",    REG_OFFSET(__rip),    8, 16, 16},
    { "eflags", REG_OFFSET(__rflags), 4, 49, -1},

#elif (defined(__FreeBSD__) || defined(__NetBSD__)) && defined(__i386__)
#   define REG_SP r_esp
#   define REG_BP r_ebp
#   define REG_IP r_eip
    { "eax",    REG_OFFSET(r_eax),    4,  0,  0},
    { "ecx",    REG_OFFSET(r_ecx),    4,  1,  1},
    { "edx",    REG_OFFSET(r_edx),    4,  2,  2},
    { "ebx",    REG_OFFSET(r_ebx),    4,  3,  3},
    { "esp",    REG_OFFSET(r_esp),    4,  4,  4},
    { "ebp",    REG_OFFSET(r_ebp),    4,  5,  5},
    { "esi",    REG_OFFSET(r_esi),    4,  6,  6},
    { "edi",    REG_OFFSET(r_edi),    4,  7,  7},
    { "eip",    REG_OFFSET(r_eip),    4,  8,  8},
    { "eflags", REG_OFFSET(r_eflags), 4,  9,  9},

#elif defined(_WRS_KERNEL) && defined(__i386__)
#   define REG_SP esp
#   define REG_BP ebp
#   define REG_IP eip
    { "eax",    REG_OFFSET(eax),      4,  0,  0},
    { "ebx",    REG_OFFSET(ebx),      4,  3,  3},
    { "ecx",    REG_OFFSET(ecx),      4,  1,  1},
    { "edx",    REG_OFFSET(edx),      4,  2,  2},
    { "esp",    REG_OFFSET(esp),      4,  4,  4},
    { "ebp",    REG_OFFSET(ebp),      4,  5,  5},
    { "esi",    REG_OFFSET(esi),      4,  6,  6},
    { "edi",    REG_OFFSET(edi),      4,  7,  7},
    { "eip",    REG_OFFSET(eip),      4,  8,  8},
    { "eflags", REG_OFFSET(eflags),   4,  9,  9},

#elif defined(__x86_64__)
#   define REG_SP user.regs.rsp
#   define REG_BP user.regs.rbp
#   define REG_IP user.regs.rip
    { "rax",    REG_OFFSET(user.regs.rax),      8,  0,  0},
    { "rdx",    REG_OFFSET(user.regs.rdx),      8,  1,  1},
    { "rcx",    REG_OFFSET(user.regs.rcx),      8,  2,  2},
    { "rbx",    REG_OFFSET(user.regs.rbx),      8,  3,  3},
    { "rsi",    REG_OFFSET(user.regs.rsi),      8,  4,  4},
    { "rdi",    REG_OFFSET(user.regs.rdi),      8,  5,  5},
    { "rbp",    REG_OFFSET(user.regs.rbp),      8,  6,  6},
    { "rsp",    REG_OFFSET(user.regs.rsp),      8,  7,  7},
    { "r8",     REG_OFFSET(user.regs.r8),       8,  8,  8},
    { "r9",     REG_OFFSET(user.regs.r9),       8,  9,  9},
    { "r10",    REG_OFFSET(user.regs.r10),      8, 10, 10},
    { "r11",    REG_OFFSET(user.regs.r11),      8, 11, 11},
    { "r12",    REG_OFFSET(user.regs.r12),      8, 12, 12},
    { "r13",    REG_OFFSET(user.regs.r13),      8, 13, 13},
    { "r14",    REG_OFFSET(user.regs.r14),      8, 14, 14},
    { "r15",    REG_OFFSET(user.regs.r15),      8, 15, 15},
    { "rip",    REG_OFFSET(user.regs.rip),      8, 16, 16},
    { "eflags", REG_OFFSET(user.regs.eflags),   4, 49, -1},
    { "es",     REG_OFFSET(user.regs.es),       2, 50, -1},
    { "cs",     REG_OFFSET(user.regs.cs),       2, 51, -1},
    { "ss",     REG_OFFSET(user.regs.ss),       2, 52, -1},
    { "ds",     REG_OFFSET(user.regs.ds),       2, 53, -1},
    { "fs",     REG_OFFSET(user.regs.fs),       2, 54, -1},
    { "gs",     REG_OFFSET(user.regs.gs),       2, 55, -1},
    { "fs_base", REG_OFFSET(user.regs.fs_base), 8, 58, -1},
    { "gs_base", REG_OFFSET(user.regs.gs_base), 8, 59, -1},

    { "fpu",    0, 0, -1, -1, 0, 0, 1, 1 },

    { "f0",     REG_OFFSET(fp.st_space) +   0, 10, 33, 33, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f1",     REG_OFFSET(fp.st_space) +  16, 10, 34, 34, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f2",     REG_OFFSET(fp.st_space) +  32, 10, 35, 35, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f3",     REG_OFFSET(fp.st_space) +  48, 10, 36, 36, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f4",     REG_OFFSET(fp.st_space) +  64, 10, 37, 37, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f5",     REG_OFFSET(fp.st_space) +  80, 10, 38, 38, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f6",     REG_OFFSET(fp.st_space) +  96, 10, 39, 39, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "f7",     REG_OFFSET(fp.st_space) + 112, 10, 40, 40, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },

    { "cwd",    REG_OFFSET(fp.cwd),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "swd",    REG_OFFSET(fp.swd),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "ftw",    REG_OFFSET(fp.ftw),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "fop",    REG_OFFSET(fp.fop),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "rip",    REG_OFFSET(fp.rip),  8, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "rdp",    REG_OFFSET(fp.rdp),  8, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },

    { "mxcsr",      REG_OFFSET(fp.mxcsr),       4, 64, 64, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },
    { "mxcr_mask",  REG_OFFSET(fp.mxcr_mask),   4, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 26 },

    { "xmm",    0, 0, -1, -1, 0, 0, 1, 1 },

    { "xmm0",   REG_OFFSET(fp.xmm_space) +   0, 16, 17, 17, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm1",   REG_OFFSET(fp.xmm_space) +  16, 16, 18, 18, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm2",   REG_OFFSET(fp.xmm_space) +  32, 16, 19, 19, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm3",   REG_OFFSET(fp.xmm_space) +  48, 16, 20, 20, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm4",   REG_OFFSET(fp.xmm_space) +  64, 16, 21, 21, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm5",   REG_OFFSET(fp.xmm_space) +  80, 16, 22, 22, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm6",   REG_OFFSET(fp.xmm_space) +  96, 16, 23, 23, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm7",   REG_OFFSET(fp.xmm_space) + 112, 16, 24, 24, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm8",   REG_OFFSET(fp.xmm_space) + 128, 16, 25, 25, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm9",   REG_OFFSET(fp.xmm_space) + 144, 16, 26, 26, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm10",  REG_OFFSET(fp.xmm_space) + 160, 16, 27, 27, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm11",  REG_OFFSET(fp.xmm_space) + 176, 16, 28, 28, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm12",  REG_OFFSET(fp.xmm_space) + 192, 16, 29, 29, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm13",  REG_OFFSET(fp.xmm_space) + 208, 16, 30, 30, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm14",  REG_OFFSET(fp.xmm_space) + 224, 16, 31, 31, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },
    { "xmm15",  REG_OFFSET(fp.xmm_space) + 240, 16, 32, 32, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 43 },

    { "debug",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 60 */

    { "dr0",    REG_OFFSET(user.u_debugreg[0]), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 60 },
    { "dr1",    REG_OFFSET(user.u_debugreg[1]), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 60 },
    { "dr2",    REG_OFFSET(user.u_debugreg[2]), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 60 },
    { "dr3",    REG_OFFSET(user.u_debugreg[3]), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 60 },
    { "dr6",    REG_OFFSET(user.u_debugreg[6]), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 60 },
    { "dr7",    REG_OFFSET(user.u_debugreg[7]), 8, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 60 },

#elif defined(__i386__)
#   define REG_SP user.regs.esp
#   define REG_BP user.regs.ebp
#   define REG_IP user.regs.eip
    { "eax",    REG_OFFSET(user.regs.eax),      4,  0,  0},
    { "ebx",    REG_OFFSET(user.regs.ebx),      4,  3,  3},
    { "ecx",    REG_OFFSET(user.regs.ecx),      4,  1,  1},
    { "edx",    REG_OFFSET(user.regs.edx),      4,  2,  2},
    { "esp",    REG_OFFSET(user.regs.esp),      4,  4,  4},
    { "ebp",    REG_OFFSET(user.regs.ebp),      4,  5,  5},
    { "esi",    REG_OFFSET(user.regs.esi),      4,  6,  6},
    { "edi",    REG_OFFSET(user.regs.edi),      4,  7,  7},
    { "eip",    REG_OFFSET(user.regs.eip),      4,  8,  8},
    { "eflags", REG_OFFSET(user.regs.eflags),   4,  9,  9},
    { "ds",     REG_OFFSET(user.regs.xds),      2, -1, -1},
    { "es",     REG_OFFSET(user.regs.xes),      2, -1, -1},
    { "fs",     REG_OFFSET(user.regs.xfs),      2, -1, -1},
    { "gs",     REG_OFFSET(user.regs.xgs),      2, -1, -1},
    { "cs",     REG_OFFSET(user.regs.xcs),      2, -1, -1},
    { "ss",     REG_OFFSET(user.regs.xss),      2, -1, -1},

    { "ax",     REG_OFFSET(user.regs.eax),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 0 },
    { "al",     REG_OFFSET(user.regs.eax),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 16 },
    { "ah",     REG_OFFSET(user.regs.eax) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 16 },

    { "bx",     REG_OFFSET(user.regs.ebx),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 1 },
    { "bl",     REG_OFFSET(user.regs.ebx),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 19 },
    { "bh",     REG_OFFSET(user.regs.ebx) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 19 },

    { "cx",     REG_OFFSET(user.regs.ecx),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 2 },
    { "cl",     REG_OFFSET(user.regs.ecx),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 22 },
    { "ch",     REG_OFFSET(user.regs.ecx) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 22 },

    { "dx",     REG_OFFSET(user.regs.edx),      2, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 3 },
    { "dl",     REG_OFFSET(user.regs.edx),      1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 25 },
    { "dh",     REG_OFFSET(user.regs.edx) + 1,  1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 25 },

    { "fpu",    0, 0, -1, -1, 0, 0, 1, 1 },

    { "f0",     REG_OFFSET(other.st_space) +   0, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f1",     REG_OFFSET(other.st_space) +  16, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f2",     REG_OFFSET(other.st_space) +  32, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f3",     REG_OFFSET(other.st_space) +  48, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f4",     REG_OFFSET(other.st_space) +  64, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f5",     REG_OFFSET(other.st_space) +  80, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f6",     REG_OFFSET(other.st_space) +  96, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "f7",     REG_OFFSET(other.st_space) + 112, 10, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },

    { "cwd",    REG_OFFSET(other.cwd),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "swd",    REG_OFFSET(other.swd),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "twd",    REG_OFFSET(other.twd),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "fop",    REG_OFFSET(other.fop),  2, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "fip",    REG_OFFSET(other.fip),  4, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "fcs",    REG_OFFSET(other.fcs),  4, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "foo",    REG_OFFSET(other.foo),  4, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },
    { "fos",    REG_OFFSET(other.fos),  4, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },

    { "mxcsr",  REG_OFFSET(other.mxcsr), 4, -1, -1, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 28 },

    { "xmm",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 46 */

    { "xmm0",   REG_OFFSET(other.xmm_space) +   0, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm1",   REG_OFFSET(other.xmm_space) +  16, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm2",   REG_OFFSET(other.xmm_space) +  32, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm3",   REG_OFFSET(other.xmm_space) +  48, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm4",   REG_OFFSET(other.xmm_space) +  64, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm5",   REG_OFFSET(other.xmm_space) +  80, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm6",   REG_OFFSET(other.xmm_space) +  96, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },
    { "xmm7",   REG_OFFSET(other.xmm_space) + 112, 16, -1, -1, 0, 1, 0,  0,  0,  0,  0,  0,  0,  0,  0, regs_index + 46 },

    { "debug",    0, 0, -1, -1, 0, 0, 1, 1 }, /* 55 */

    { "dr0",    REG_OFFSET(user.u_debugreg[0]), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 55 },
    { "dr1",    REG_OFFSET(user.u_debugreg[1]), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 55 },
    { "dr2",    REG_OFFSET(user.u_debugreg[2]), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 55 },
    { "dr3",    REG_OFFSET(user.u_debugreg[3]), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 55 },
    { "dr6",    REG_OFFSET(user.u_debugreg[6]), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 55 },
    { "dr7",    REG_OFFSET(user.u_debugreg[7]), 4, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, regs_index + 55 },

#endif

    { NULL,     0,                    0,  0,  0},
};

#ifdef regs_index
#undef regs_index
#endif
RegisterDefinition * regs_index = NULL;

unsigned char BREAK_INST[] = { 0xcc };

#ifdef MDEP_OtherRegisters

#include <sys/ptrace.h>

#if !defined(PTRACE_GETFPXREGS) && !defined(PT_GETFPXREGS)
#define PTRACE_GETFPXREGS 18
#endif
#if !defined(PTRACE_SETFPXREGS) && !defined(PT_SETFPXREGS)
#define PTRACE_SETFPXREGS 19
#endif

int mdep_get_other_regs(pid_t pid, REG_SET * data,
                       size_t data_offs, size_t data_size,
                       size_t * done_offs, size_t * done_size) {
    assert(data_offs >= offsetof(REG_SET, other));
    assert(data_offs + data_size <= offsetof(REG_SET, other) + sizeof(data->other));
    if (ptrace(PTRACE_GETFPXREGS, pid, 0, &data->other) < 0) return -1;
    *done_offs = offsetof(REG_SET, other);
    *done_size = sizeof(data->other);
    return 0;
}

int mdep_set_other_regs(pid_t pid, REG_SET * data,
                       size_t data_offs, size_t data_size,
                       size_t * done_offs, size_t * done_size) {
    assert(data_offs >= offsetof(REG_SET, other));
    assert(data_offs + data_size <= offsetof(REG_SET, other) + sizeof(data->other));
    if (ptrace(PTRACE_SETFPXREGS, pid, 0, &data->other) < 0) return -1;
    *done_offs = offsetof(REG_SET, other);
    *done_size = sizeof(data->other);
    return 0;
}

#endif

#ifndef _WRS_KERNEL
#define JMPD08      0xeb
#define JMPD32      0xe9
#define PUSH_EBP    0x55
#define ENTER       0xc8
#define RET         0xc3
#define RETADD      0xc2
#endif
#define GRP5        0xff
#define JMPN        0x25
#define MOVE_mr     0x89
#define MOVE_rm     0x8b
#define REXW        0x48

static int read_stack(Context * ctx, ContextAddress addr, void * buf, size_t size) {
    if (addr == 0) {
        errno = ERR_INV_ADDRESS;
        return -1;
    }
#ifdef _WRS_KERNEL
    {
        WIND_TCB * tcb = taskTcb(get_context_task_id(ctx));
        if (addr < (ContextAddress)tcb->pStackEnd || addr > (ContextAddress)tcb->pStackBase) {
            errno = ERR_INV_ADDRESS;
            return -1;
        }
    }
#endif
    return context_read_mem(ctx, addr, buf, size);
}

static int read_reg(StackFrame * frame, RegisterDefinition * def, ContextAddress * addr) {
    uint64_t v = 0;
    int r = read_reg_value(frame, def, &v);
    *addr = (ContextAddress)v;
    return r;
}

/*
 * trace_jump - resolve any JMP instructions to final destination
 *
 * This routine returns a pointer to the next non-JMP instruction to be
 * executed if the PC were at the specified <adrs>.  That is, if the instruction
 * at <adrs> is not a JMP, then <adrs> is returned.  Otherwise, if the
 * instruction at <adrs> is a JMP, then the destination of the JMP is
 * computed, which then becomes the new <adrs> which is tested as before.
 * Thus we will eventually return the address of the first non-JMP instruction
 * to be executed.
 *
 * The need for this arises because compilers may put JMPs to instructions
 * that we are interested in, instead of the instruction itself.  For example,
 * optimizers may replace a stack pop with a JMP to a stack pop.  Or in very
 * UNoptimized code, the first instruction of a subroutine may be a JMP to
 * a PUSH %EBP MOV %ESP %EBP, instead of a PUSH %EBP MOV %ESP %EBP (compiler
 * may omit routine "post-amble" at end of parsing the routine!).  We call
 * this routine anytime we are looking for a specific kind of instruction,
 * to help handle such cases.
 *
 * RETURNS: The address that a chain of branches points to.
 */
static ContextAddress trace_jump(Context * ctx, ContextAddress addr) {
    int cnt = 0;
    /* while instruction is a JMP, get destination adrs */
    while (cnt < 100) {
        unsigned char instr;    /* instruction opcode at <addr> */
        ContextAddress dest;    /* Jump destination address */
        if (context_read_mem(ctx, addr, &instr, 1) < 0) break;

        /* If instruction is a JMP, get destination adrs */
        if (instr == JMPD08) {
            signed char disp08;
            if (context_read_mem(ctx, addr + 1, &disp08, 1) < 0) break;
            dest = addr + 2 + disp08;
        }
        else if (instr == JMPD32) {
            int32_t disp32 = 0;
            if (context_read_mem(ctx, addr + 1, &disp32, 4) < 0) break;
            dest = addr + 5 + disp32;
        }
        else if (instr == GRP5) {
            ContextAddress ptr;
            if (context_read_mem(ctx, addr + 1, &instr, 1) < 0) break;
            if (instr != JMPN) break;
            if (context_read_mem(ctx, addr + 2, &ptr, sizeof(ptr)) < 0) break;
            if (context_read_mem(ctx, ptr, &dest, sizeof(dest)) < 0) break;
        }
        else if (instr == MOVE_rm) {
            unsigned char modrm = 0;
            unsigned char mod = 0;
            unsigned char reg = 0;
            unsigned char rm = 0;
            if (context_read_mem(ctx, addr + 1, &modrm, 1) < 0) break;
            mod = modrm >> 6;
            reg = (modrm >> 3) & 7u;
            rm = modrm & 7u;
            if (reg == 4 || reg == 5) {
                /* move to SP or BP */
                break;
            }
            if (mod == 0 && (rm == 5 || rm == 6)) {
                break;
            }
            if (mod == 0) {
                dest = addr + 2;
                if (rm == 4) dest++;
            }
            else if (mod == 1) {
                dest = addr + 3;
                if (rm == 4) dest++;
            }
            else if (mod == 2) {
                dest = addr + 6;
                if (rm == 4) dest++;
            }
            else if (mod == 3) {
                dest = addr + 2;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
        if (dest == addr) break;
        addr = dest;
        cnt++;
    }
    return addr;
}

static int is_func_entry(unsigned char * code) {
    if (*code != PUSH_EBP) return 0;
    code++;
    if (*code == REXW) code++;
    if (code[0] == MOVE_mr && code[1] == 0xe5) return 1;
    if (code[0] == MOVE_rm && code[1] == 0xec) return 1;
    return 0;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {

    static RegisterDefinition * pc_def = NULL;
    static RegisterDefinition * sp_def = NULL;
    static RegisterDefinition * bp_def = NULL;

    ContextAddress reg_pc = 0;
    ContextAddress reg_bp = 0;

    ContextAddress dwn_pc = 0;
    ContextAddress dwn_sp = 0;
    ContextAddress dwn_bp = 0;

    Context * ctx = frame->ctx;

    if (pc_def == NULL) {
        RegisterDefinition * r;
        for (r = get_reg_definitions(ctx); r->name != NULL; r++) {
            if (r->offset == offsetof(REG_SET, REG_IP)) pc_def = r;
            if (r->offset == offsetof(REG_SET, REG_SP)) sp_def = r;
            if (r->offset == offsetof(REG_SET, REG_BP)) bp_def = r;
        }
    }

    if (read_reg(frame, pc_def, &reg_pc) < 0) return 0;
    if (read_reg(frame, bp_def, &reg_bp) < 0) return 0;

    if (frame->is_top_frame) {
        /* Top frame */
        ContextAddress reg_sp = 0;
        ContextAddress addr = trace_jump(ctx, reg_pc);
#if ENABLE_Symbols
        ContextAddress plt = is_plt_section(ctx, addr);
#else
        ContextAddress plt = 0;
#endif

        if (read_reg(frame, sp_def, &reg_sp) < 0) return 0;
        /*
         * we don't have a stack frame in a few restricted but useful cases:
         *  1) we are at a PUSH %EBP MOV %ESP %EBP or RET or ENTER instruction,
         *  2) we are at the first instruction of a subroutine (this may NOT be
         *     a PUSH %EBP MOV %ESP %EBP instruction with some compilers)
         *  3) we are inside PLT entry
         */
        if (plt) {
            /* TODO: support for large code model PLT */
            if (addr - plt == 0) {
                dwn_sp = reg_sp + sizeof(ContextAddress) * 2;
            }
            else if (addr - plt < 16) {
                dwn_sp = reg_sp + sizeof(ContextAddress) * 3;
            }
            else if ((addr - plt - 16) % 16 < 11) {
                dwn_sp = reg_sp + sizeof(ContextAddress);
            }
            else {
                dwn_sp = reg_sp + sizeof(ContextAddress) * 2;
            }
            dwn_bp = reg_bp;
        }
        else {
            unsigned char code[5];

            if (context_read_mem(ctx, addr - 1, code, sizeof(code)) < 0) return -1;

            if (is_func_entry(code + 1) || code[1] == ENTER || code[1] == RET || code[1] == RETADD) {
                dwn_sp = reg_sp + sizeof(ContextAddress);
                dwn_bp = reg_bp;
            }
            else if (is_func_entry(code)) {
                dwn_sp = reg_sp + sizeof(ContextAddress) * 2;
                dwn_bp = reg_bp;
            }
            else if (reg_bp != 0) {
                dwn_sp = reg_bp + sizeof(ContextAddress) * 2;
                if (read_stack(ctx, reg_bp, &dwn_bp, sizeof(ContextAddress)) < 0) dwn_bp = 0;
            }
        }
    }
    else {
        if (read_stack(ctx, reg_bp, &dwn_bp, sizeof(ContextAddress)) < 0) dwn_bp = 0;
        else dwn_sp = reg_bp + sizeof(ContextAddress) * 2;
    }

    if (read_stack(ctx, dwn_sp - sizeof(ContextAddress), &dwn_pc, sizeof(ContextAddress)) < 0) dwn_pc = 0;

    if (dwn_bp < reg_bp) dwn_bp = 0;

    if (dwn_pc != 0) {
        if (write_reg_value(down, pc_def, dwn_pc) < 0) return -1;
        if (dwn_sp != 0 && write_reg_value(down, sp_def, dwn_sp) < 0) return -1;
        if (dwn_bp != 0 && write_reg_value(down, bp_def, dwn_bp) < 0) return -1;
        frame->fp = dwn_sp;
    }

    return 0;
}

RegisterDefinition * get_PC_definition(Context * ctx) {
    static RegisterDefinition * reg_def = NULL;
    if (reg_def == NULL) {
        RegisterDefinition * r;
        for (r = get_reg_definitions(ctx); r->name != NULL; r++) {
            if (r->offset == offsetof(REG_SET, REG_IP)) {
                reg_def = r;
                break;
            }
        }
    }
    return reg_def;
}

static void ini_xmm_regs(void) {
    static int sub_xmm_sizes[] = {8, 16, 32, 64, -1};
    char sub_xmm_name[256];
    int ix = 0, jx = 0, max_sub_xmm = 0, xmm_ix = 0, sub_xmm_sizes_ix = 0;
    RegisterDefinition * cur_reg_def = NULL;

    /* seek xmm0 definition */
    regs_index = regs_def;
    while (regs_index[xmm_ix].name != NULL && (strcmp(regs_index[xmm_ix].name, "xmm0") != 0)) xmm_ix ++;
    if (regs_index[xmm_ix].name == NULL) return;

    /* allocate a new register definition array */
    for (ix = 0; sub_xmm_sizes[ix] != -1; ix ++) {
        max_sub_xmm += XMM_SIZE / sub_xmm_sizes[ix];
    }
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(regs_def) + (max_sub_xmm + ix)* XMM_REGS * sizeof(RegisterDefinition));

    for (ix = 0; regs_def[ix].name != NULL; ix ++) {
        regs_index[ix] = regs_def[ix]; /* keep references to regs_def array (name, role), as it is a static array */
        if (regs_def[ix].parent != NULL) {
            regs_index[ix].parent = regs_index + (regs_def[ix].parent - regs_def);
        }
    }

    /* add the xmm sub-registers combinations */
    cur_reg_def = regs_index + ix;
    for (ix = 0; ix < XMM_REGS; ix ++) {
        for (sub_xmm_sizes_ix = 0; sub_xmm_sizes[sub_xmm_sizes_ix] != -1; sub_xmm_sizes_ix ++) {
            int sub_xmm_ix = 0;
            int nb_sub_xmm = XMM_SIZE / sub_xmm_sizes[sub_xmm_sizes_ix];
            sprintf(sub_xmm_name, "w%d", sub_xmm_sizes[sub_xmm_sizes_ix]);
            cur_reg_def->name = loc_strdup(sub_xmm_name);
            cur_reg_def->dwarf_id = -1;
            cur_reg_def->parent = regs_index + xmm_ix;
            cur_reg_def ++;
            for (sub_xmm_ix = 0; sub_xmm_ix < nb_sub_xmm; sub_xmm_ix ++) {
                sprintf(sub_xmm_name, "f%d", sub_xmm_ix);
                cur_reg_def->name = loc_strdup(sub_xmm_name);
                cur_reg_def->size = sub_xmm_sizes[sub_xmm_sizes_ix] / 8;
                cur_reg_def->offset = regs_index[xmm_ix].offset + sub_xmm_ix * cur_reg_def->size;
                cur_reg_def->dwarf_id = -1;
                cur_reg_def->eh_frame_id = -1;
                cur_reg_def->big_endian = regs_index[xmm_ix].big_endian;
                cur_reg_def->fp_value = regs_index[xmm_ix].fp_value;
                cur_reg_def->no_read = regs_index[xmm_ix].no_read;
                cur_reg_def->no_write = regs_index[xmm_ix].no_write;
                cur_reg_def->read_once = regs_index[xmm_ix].read_once;
                cur_reg_def->write_once = regs_index[xmm_ix].write_once;
                cur_reg_def->side_effects = regs_index[xmm_ix].side_effects;
                cur_reg_def->volatile_value = regs_index[xmm_ix].volatile_value;
                cur_reg_def->left_to_right = regs_index[xmm_ix].left_to_right;
                cur_reg_def->first_bit = regs_index[xmm_ix].first_bit;
                cur_reg_def->parent = cur_reg_def - sub_xmm_ix - 1;
                cur_reg_def ++; jx ++;
            }
            if (jx % max_sub_xmm == 0) xmm_ix ++;
        }
    }
}

#if ENABLE_HardwareBreakpoints

#define MAX_HW_BPS 4
#define ENABLE_BP_ACCESS_INSTRUCTION 0

typedef struct ContextExtensionX86 {
    ContextBreakpoint * triggered_hw_bps[MAX_HW_BPS + 1];
    unsigned            hw_bps_regs_generation;

    ContextBreakpoint * hw_bps[MAX_HW_BPS];
    unsigned            hw_idx[MAX_HW_BPS];
    unsigned            hw_bps_generation;
} ContextExtensionX86;

static size_t context_extension_offset = 0;

#define EXT(ctx) ((ContextExtensionX86 *)((char *)(ctx) + context_extension_offset))

static RegisterDefinition * get_DR_definition(unsigned no) {
    static RegisterDefinition * dr_defs[8];
    if (no > 7) return NULL;
    if (dr_defs[no] == NULL) {
        RegisterDefinition * def = regs_index;
        while (def->name) {
            if (def->name[0] == 'd' && def->name[1] == 'r' &&
                def->name[2] == '0' + (int)no && def->name[3] == 0) {
                dr_defs[no] = def;
                break;
            }
            def++;
        }
    }
    return dr_defs[no];
}

static int skip_read_only_breakpoint(Context * ctx, uint8_t dr6, ContextBreakpoint * bp) {
    int i;
    int read_write_hit = 0;
    ContextExtensionX86 * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));

    for (i = 0; i < MAX_HW_BPS; i++) {
        if (bps->hw_bps[i] != bp) continue;
        if ((dr6 & (1 << i)) == 0) continue;
        if (bps->hw_idx[i] == 0) return 1;
        read_write_hit = 1;
    }
    if (!read_write_hit) return 1;
    if (ctx->stopped_by_cb != NULL) {
        ContextBreakpoint ** p = ctx->stopped_by_cb;
        while (*p != NULL) if (*p++ == bp) return 1;
    }
    return 0;
}

static int set_debug_regs(Context * ctx, int check_ip, int * step_over_hw_bp) {
    int i;
    uint32_t dr7 = 0;
    ContextAddress ip = 0;
    ContextExtensionX86 * ext = EXT(ctx);
    ContextExtensionX86 * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));

    if (check_ip) {
        *step_over_hw_bp = 0;
        if (context_read_reg(ctx, get_PC_definition(ctx), 0, sizeof(ip), &ip) < 0) return -1;
    }

    for (i = 0; i < MAX_HW_BPS; i++) {
        ContextBreakpoint * bp = bps->hw_bps[i];
        if (bp == NULL) {
            /* nothing */
        }
        else if (check_ip && bp->address == ip && (bp->access_types & CTX_BP_ACCESS_INSTRUCTION)) {
            /* Skipping the breakpoint */
            *step_over_hw_bp = 1;
        }
        else {
            if (context_write_reg(ctx, get_DR_definition(i), 0, sizeof(bp->address), &bp->address) < 0) return -1;
            dr7 |= (uint32_t)1 << (i * 2);
            if (bp->access_types == (CTX_BP_ACCESS_INSTRUCTION | CTX_BP_ACCESS_VIRTUAL)) {
                /* nothing */
            }
            else if (bp->access_types == (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_VIRTUAL)) {
                if (bps->hw_idx[i] == 0) {
                    dr7 |= (uint32_t)1 << (i * 4 + 16);
                }
                else {
                    dr7 |= (uint32_t)3 << (i * 4 + 16);
                }
                dr7 |= 0x100u;
            }
            else if (bp->access_types == (CTX_BP_ACCESS_DATA_WRITE | CTX_BP_ACCESS_VIRTUAL)) {
                dr7 |= (uint32_t)1 << (i * 4 + 16);
                dr7 |= 0x100u;
            }
            else if (bp->access_types == (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_DATA_WRITE | CTX_BP_ACCESS_VIRTUAL)) {
                dr7 |= (uint32_t)3 << (i * 4 + 16);
                dr7 |= 0x100u;
            }
            else {
                set_errno(ERR_UNSUPPORTED, "Invalid hardware breakpoint: unsupported access mode");
                return -1;
            }
            if (bp->length == 1) {
                /* nothing */
            }
            else if (bp->length == 2) {
                dr7 |= (uint32_t)1 << (i * 4 + 18);
            }
            else if (bp->length == 4) {
                dr7 |= (uint32_t)3 << (i * 4 + 18);
            }
            else if (bp->length == 8) {
                dr7 |= (uint32_t)2 << (i * 4 + 18);
            }
            else {
                set_errno(ERR_UNSUPPORTED, "Invalid hardware breakpoint: unsupported length");
                return -1;
            }
        }
    }
    if (context_write_reg(ctx, get_DR_definition(7), 0, sizeof(dr7), &dr7) < 0) return -1;
    ext->hw_bps_regs_generation = bps->hw_bps_generation;
    if (check_ip && *step_over_hw_bp) ext->hw_bps_regs_generation--;
    return 0;
}

int cpu_bp_get_capabilities(Context * ctx) {
    if (get_DR_definition(0) == NULL) return 0;
    if (ctx != context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT)) return 0;
    return
        CTX_BP_ACCESS_DATA_READ |
        CTX_BP_ACCESS_DATA_WRITE |
#if ENABLE_BP_ACCESS_INSTRUCTION
        CTX_BP_ACCESS_INSTRUCTION |
#endif
        CTX_BP_ACCESS_VIRTUAL;
}

int cpu_bp_plant(ContextBreakpoint * bp) {
    Context * ctx = bp->ctx;
    assert(bp->access_types);
    if (bp->access_types & CTX_BP_ACCESS_VIRTUAL) {
        ContextExtensionX86 * bps = EXT(ctx);
        if (bp->length <= 8 && ((1u << bp->length) & 0x116u)) {
            unsigned i;
            unsigned n = 1;
            unsigned m = 0;
            if (bp->access_types == (CTX_BP_ACCESS_INSTRUCTION | CTX_BP_ACCESS_VIRTUAL)) {
#if ENABLE_BP_ACCESS_INSTRUCTION
                /* Don't use more then 2 HW slots for instruction access breakpoints */
                int cnt = 0;
                for (i = 0; i < MAX_HW_BPS; i++) {
                    assert(bps->hw_bps[i] != bp);
                    if (bps->hw_bps[i] == NULL) continue;
                    if ((bps->hw_bps[i]->access_types & CTX_BP_ACCESS_INSTRUCTION) == 0) continue;
                    cnt++;
                }
                if (cnt >= MAX_HW_BPS / 2) {
                    errno = ERR_UNSUPPORTED;
                    return -1;
                }
#else
                errno = ERR_UNSUPPORTED;
                return -1;
#endif
            }
            else if (bp->access_types == (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_VIRTUAL)) {
                n = 2;
            }
            else if (bp->access_types != (CTX_BP_ACCESS_DATA_WRITE | CTX_BP_ACCESS_VIRTUAL) &&
                        bp->access_types != (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_DATA_WRITE | CTX_BP_ACCESS_VIRTUAL)) {
                errno = ERR_UNSUPPORTED;
                return -1;
            }
            for (i = 0; i < MAX_HW_BPS && m < n; i++) {
                assert(bps->hw_bps[i] != bp);
                if (bps->hw_bps[i] == NULL) {
                    bps->hw_bps[i] = bp;
                    bps->hw_idx[i] = m++;
                    bp->id = i;
                }
            }
            if (m == n) {
                LINK * l = context_root.next;
                bps->hw_bps_generation++;
                while (l != &context_root) {
                    Context * c = ctxl2ctxp(l);
                    if (c->stopped && context_get_group(c, CONTEXT_GROUP_BREAKPOINT) == ctx) {
                        if (set_debug_regs(c, 0, NULL) < 0) {
                            for (i = 0; i < MAX_HW_BPS && n > 0; i++) {
                                if (bps->hw_bps[i] == bp) bps->hw_bps[i] = NULL;
                            }
                            return -1;
                        }
                    }
                    l = l->next;
                }
                return 0;
            }
            for (i = 0; i < MAX_HW_BPS && n > 0; i++) {
                if (bps->hw_bps[i] == bp) bps->hw_bps[i] = NULL;
            }
        }
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int cpu_bp_remove(ContextBreakpoint * bp) {
    int i;
    LINK * l = NULL;
    Context * ctx = bp->ctx;
    ContextExtensionX86 * bps = EXT(ctx);
    for (i = 0; i < MAX_HW_BPS; i++) {
        if (bps->hw_bps[i] == bp) {
            bps->hw_bps[i] = NULL;
            bps->hw_bps_generation++;
        }
    }
    l = context_root.next;
    while (l != &context_root) {
        Context * c = ctxl2ctxp(l);
        if (c->stopped && context_get_group(c, CONTEXT_GROUP_BREAKPOINT) == ctx) {
            if (set_debug_regs(c, 0, NULL) < 0) return -1;
        }
        l = l->next;
    }
    return 0;
}

int cpu_bp_on_resume(Context * ctx, int * single_step) {
    /* Update debug registers */
    ContextExtensionX86 * ext = EXT(ctx);
    ContextExtensionX86 * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
    if (ctx->stopped_by_cb != NULL || ext->hw_bps_regs_generation != bps->hw_bps_generation) {
        if (set_debug_regs(ctx, 1, single_step) < 0) return -1;
    }
    return 0;
}

int cpu_bp_on_suspend(Context * ctx, int * triggered) {
    int cb_found = 0;
    uint8_t dr6 = 0;

    if (ctx->exiting) return 0;
    if (context_read_reg(ctx, get_DR_definition(6), 0, sizeof(dr6), &dr6) < 0) return -1;

    if (dr6 & 0xfu) {
        int i, j = 0;
        ContextExtensionX86 * ext = EXT(ctx);
        ContextExtensionX86 * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
        for (i = 0; i < MAX_HW_BPS; i++) {
            if (dr6 & ((uint32_t)1 << i)) {
                ContextBreakpoint * bp = bps->hw_bps[i];
                if (bp == NULL) continue;
                cb_found = 1;
                if (bp->access_types == (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_VIRTUAL)) {
                    if (skip_read_only_breakpoint(ctx, dr6, bp)) continue;
                }
                ctx->stopped_by_cb = ext->triggered_hw_bps;
                ctx->stopped_by_cb[j++] = bp;
                ctx->stopped_by_cb[j] = NULL;
            }
        }
        dr6 = 0;
        if (context_write_reg(ctx, get_DR_definition(6), 0, sizeof(dr6), &dr6) < 0) return -1;
    }
    *triggered = cb_found;
    return 0;
}

#endif /* ENABLE_HardwareBreakpoints */

void ini_cpudefs_mdep(void) {
    ini_xmm_regs ();
#if ENABLE_HardwareBreakpoints
    context_extension_offset = context_extension(sizeof(ContextExtensionX86));
#endif
}

#endif
#endif
