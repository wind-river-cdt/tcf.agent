/*******************************************************************************
 * Copyright (c) 2013 Xilinx, Inc. and others.
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
 *     Xilinx - initial API and implementation
 *******************************************************************************/

/*
 * This module implements stack crawl for ARM processor.
 */

/*
 * This code is based on ideas from a work that was published by
 * Michael McTernan with following disclaimer:
 *
 * The source code for the stack unwinder is released as public domain.
 * This means that there is no copyright and anyone is able to take a
 * copy for free and use it as they wish, with or without modifications,
 * and in any context they like, commercially or otherwise.
 *
 * The only limitation is that I don't guarantee that the software is fit
 * for any purpose or accept any liability for it's use or misuse -
 * the software is without warranty.
 *
 * Michael McTernan
 * Michael.McTernan.2001@cs.bris.ac.uk
 */

#include <tcf/config.h>

#if ENABLE_DebugContext

#include <assert.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/trace.h>
#include <machine/arm/tcf/stack-crawl-arm.h>

#define USE_MEM_CACHE        1
#define MEM_HASH_SIZE       61
#define BRANCH_LIST_SIZE    12

#define REG_VAL_ADDR         1
#define REG_VAL_STACK        2
#define REG_VAL_OTHER        3

typedef struct {
    uint32_t v;
    uint32_t o;
} RegData;

typedef struct {
    uint32_t v[MEM_HASH_SIZE]; /* Value */
    uint32_t a[MEM_HASH_SIZE]; /* Address */
    uint8_t  used[MEM_HASH_SIZE];
    uint8_t  tracked[MEM_HASH_SIZE];
} MemData;

typedef struct {
    uint32_t addr;
    RegData reg_data[16];
    RegData cpsr_data;
    MemData mem_data;
} BranchData;

static Context * stk_ctx = NULL;
static RegData reg_data[16];
static RegData cpsr_data;
static MemData mem_data;
static unsigned mem_cache_idx = 0;
static int trace_return = 0;
static int trace_branch = 0;

static unsigned branch_pos = 0;
static unsigned branch_cnt = 0;
static BranchData branch_data[BRANCH_LIST_SIZE];

#if USE_MEM_CACHE

typedef struct {
    uint32_t addr;
    uint32_t size;
    uint8_t data[64];
} MemCache;

#define MEM_CACHE_SIZE       8
static MemCache mem_cache[MEM_CACHE_SIZE];

static int read_byte(uint32_t addr, uint8_t * bt) {
    unsigned i = 0;
    MemCache * c = NULL;

    if (addr == 0) {
        errno = ERR_INV_ADDRESS;
        return -1;
    }
    for (i = 0; i < MEM_CACHE_SIZE; i++) {
        c = mem_cache + mem_cache_idx;
        if (c->addr <= addr && (c->addr + c->size < c->addr || c->addr + c->size > addr)) {
            *bt = c->data[addr - c->addr];
            return 0;
        }
        mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    }
    mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    c = mem_cache + mem_cache_idx;
    c->addr = addr;
    c->size = sizeof(c->data);
    if (context_read_mem(stk_ctx, addr, c->data, c->size) < 0) {
        int error = errno;
        MemoryErrorInfo info;
        if (context_get_mem_error_info(&info) < 0 || info.size_valid == 0) {
            c->size = 0;
            errno = error;
            return -1;
        }
        c->size = info.size_valid;
    }
    *bt = c->data[0];
    return 0;
}

static int read_half(uint32_t addr, uint16_t * h) {
    unsigned i;
    uint16_t n = 0;
    for (i = 0; i < 2; i++) {
        uint8_t bt = 0;
        if (read_byte(addr + i, &bt) < 0) return -1;
        n |= (uint32_t)bt << (i * 8);
    }
    *h = n;
    return 0;
}

static int read_word(uint32_t addr, uint32_t * w) {
    unsigned i;
    uint32_t n = 0;
    for (i = 0; i < 4; i++) {
        uint8_t bt = 0;
        if (read_byte(addr + i, &bt) < 0) return -1;
        n |= (uint32_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}

#else

static int read_half(uint32_t addr, uint16_t * h) {
    uint8_t buf[2];
    if (addr == 0) {
        errno = ERR_INV_ADDRESS;
        return -1;
    }
    if (context_read_mem(stk_ctx, addr, buf, 2) < 0) return -1;
    *h = (uint32_t)buf[0] | (buf[1] << 8);
    return 0;
}

static int read_word(uint32_t addr, uint32_t * w) {
    uint8_t buf[4];
    if (addr == 0) {
        errno = ERR_INV_ADDRESS;
        return -1;
    }
    if (context_read_mem(stk_ctx, addr, buf, 4) < 0) return -1;
    *w = (uint32_t)buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
    return 0;
}

#endif /* USE_MEM_CACHE */

static int mem_hash_index(const uint32_t addr) {
    int v = addr % MEM_HASH_SIZE;
    int s = v;

    do {
        /* Check if the element is occupied */
        if (mem_data.used[s]) {
            /* Check if it is occupied with the sought data */
            if (mem_data.a[s] == addr)  return s;
        }
        else {
            /* Item is free, this is where the item should be stored */
            return s;
        }

        /* Search the next entry */
        s++;
        if (s > MEM_HASH_SIZE) s = 0;
    }
    while(s != v);

    /* Search failed, hash is full and the address not stored */
    return -1;
}

static int mem_hash_read(uint32_t addr, uint32_t * data, int * tracked) {
    int i = mem_hash_index(addr);

    if (i >= 0 && mem_data.used[i] && mem_data.a[i] == addr) {
        *data    = mem_data.v[i];
        *tracked = mem_data.tracked[i];
        return 1;
    }

    /* Address not found in the hash */
    return 0;
}

static int mem_hash_write(uint32_t addr, uint32_t value, int valid) {
    int i = mem_hash_index(addr);

    if (i < 0) return 0;
    /* Store the item */
    mem_data.used[i] = 1;
    mem_data.a[i] = addr;
    mem_data.v[i] = valid ? value : 0;
    mem_data.tracked[i] = (uint8_t)valid;
    return 1;
}

static int load_reg(uint32_t addr, int r) {
    int tracked = 0;

    /* Check if the value can be found in the hash */
    if (mem_hash_read(addr, &reg_data[r].v, &tracked)) {
        reg_data[r].o = tracked ? REG_VAL_OTHER : 0;
    }
    else {
        /* Not in the hash, so read from real memory */
        reg_data[r].o = 0;
        if (read_word(addr, &reg_data[r].v) < 0) return -1;
        reg_data[r].o = REG_VAL_OTHER;
    }
    return 0;
}

static int load_reg_lazy(uint32_t addr, int r) {
    reg_data[r].o = REG_VAL_ADDR;
    reg_data[r].v = addr;
    return 0;
}

static int chk_loaded(int r) {
    if (reg_data[r].o != REG_VAL_ADDR && reg_data[r].o != REG_VAL_STACK) return 0;
    return load_reg(reg_data[r].v, r);
}

static int store_reg(uint32_t addr, int r) {
    unsigned i;
    if (chk_loaded(r) < 0) return -1;
    assert(reg_data[r].o != REG_VAL_ADDR);
    assert(reg_data[r].o != REG_VAL_STACK);
    for (i = 0; i < 16; i++) {
        if (reg_data[i].o != REG_VAL_ADDR && reg_data[i].o != REG_VAL_STACK) continue;
        if (reg_data[i].v >= addr + 4) continue;
        if (reg_data[i].v + 4 <= addr) continue;
        if (load_reg(reg_data[i].v, r) < 0) return -1;
    }
    if (!mem_hash_write(addr, reg_data[r].v, reg_data[r].o != 0)) {
        set_errno(ERR_OTHER, "Memory hash overflow");
        return -1;
    }
    return 0;
}

static void add_branch(uint32_t addr) {
    if (branch_cnt < BRANCH_LIST_SIZE) {
        int add = 1;
        unsigned i = 0;
        for (i = 0; i < branch_cnt; i++) {
            BranchData * b = branch_data + i;
            if (b->addr == addr) {
                add = 0;
                break;
            }
        }
        if (add) {
            BranchData * b = branch_data + branch_cnt++;
            b->addr = addr;
            b->mem_data = mem_data;
            b->cpsr_data = cpsr_data;
            memcpy(b->reg_data, reg_data, sizeof(reg_data));
            b->reg_data[15].v = addr;
        }
    }
}

static uint32_t calc_shift(uint32_t shift_type, uint32_t shift_imm, uint32_t val) {
    switch (shift_type) {
    case 0: /* logical left */
        val = val << shift_imm;
        break;
    case 1: /* logical right */
        if (shift_imm == 0) val = 0;
        else val = val >> shift_imm;
        break;
    case 2: /* arithmetic right */
        if (shift_imm == 0) shift_imm = 32;
        if (val & 0x80000000) {
            if (shift_imm > 32) {
                val = 0xffffffff;
            }
            else {
                val = val >> shift_imm;
                val |= 0xffffffff << (32 - shift_imm);
            }
        }
        else {
            val = val >> shift_imm;
        }
        break;
    case 3: /* rotate right */
        if (shift_imm == 0) {
            /* Rotate right with extend */
            val = val >> 1;
            assert(cpsr_data.o != REG_VAL_ADDR);
            assert(cpsr_data.o != REG_VAL_STACK);
            if (cpsr_data.v & (1 << 29)) val |= 0x80000000;
        }
        else {
            shift_imm &= 0x1f;
            val = (val >> shift_imm) |
                  (val << (32 - shift_imm));
        }
        break;
    }
    return val;
}

static int trace_thumb(void) {
    uint16_t instr;

    assert(reg_data[15].o != REG_VAL_ADDR);
    assert(reg_data[15].o != REG_VAL_STACK);

    /* Check that the PC is still on Thumb alignment */
    if (!(reg_data[15].v & 0x1)) {
        set_errno(ERR_OTHER, "PC misalignment");
        return -1;
    }

    /* Attempt to read the instruction */
    if (read_half(reg_data[15].v & ~0x1, &instr) < 0) return -1;

    /* Format 1: Move shifted register
     *  LSL Rd, Rs, #Offset5
     *  LSR Rd, Rs, #Offset5
     *  ASR Rd, Rs, #Offset5
     */
    if ((instr & 0xe000) == 0x0000 && (instr & 0x1800) != 0x1800) {
        int signExtend;
        uint32_t op      = (instr & 0x1800) >> 11;
        uint32_t offset5 = (instr & 0x07c0) >>  6;
        uint32_t rs      = (instr & 0x0038) >>  3;
        uint32_t rd      = (instr & 0x0007);

        chk_loaded(rs);

        switch(op) {
        case 0: /* LSL */
            reg_data[rd].v = reg_data[rs].v << offset5;
            reg_data[rd].o = reg_data[rs].o ? REG_VAL_OTHER : 0;
            break;

        case 1: /* LSR */
            reg_data[rd].v = reg_data[rs].v >> offset5;
            reg_data[rd].o = reg_data[rs].o ? REG_VAL_OTHER : 0;
            break;

        case 2: /* ASR */
            signExtend = (reg_data[rs].v & 0x8000) != 0;
            reg_data[rd].v = reg_data[rs].v >> offset5;
            if (signExtend) reg_data[rd].v |= 0xffffffff << (32 - offset5);
            reg_data[rd].o = reg_data[rs].o ? REG_VAL_OTHER : 0;
            break;
        }
    }
    /* Format 2: add/subtract
     *  ADD Rd, Rs, Rn
     *  ADD Rd, Rs, #Offset3
     *  SUB Rd, Rs, Rn
     *  SUB Rd, Rs, #Offset3
     */
    else if ((instr & 0xf800) == 0x1800) {
        int I  = (instr & 0x0400) != 0;
        int op = (instr & 0x0200) != 0;
        uint32_t rn = (instr & 0x01c0) >> 6;
        uint32_t rs = (instr & 0x0038) >> 3;
        uint32_t rd = (instr & 0x0007);

        if (!I) {
            chk_loaded(rs);
            chk_loaded(rn);
            /* Perform calculation */
            if (op) {
                reg_data[rd].v = reg_data[rs].v - reg_data[rn].v;
            }
            else {
                reg_data[rd].v = reg_data[rs].v + reg_data[rn].v;
            }

            /* Propagate the origin */
            if (reg_data[rs].o && reg_data[rn].o) {
                reg_data[rd].o = REG_VAL_OTHER;
            }
            else {
                reg_data[rd].o = 0;
            }
        }
        else {
            chk_loaded(rs);
            /* Perform calculation */
            if (op) {
                reg_data[rd].v = reg_data[rs].v - rn;
            }
            else {
                reg_data[rd].v = reg_data[rs].v + rn;
            }

            /* Propagate the origin */
            reg_data[rd].o = reg_data[rs].o ? REG_VAL_OTHER : 0;
        }
    }
    /* Format 3: move/compare/add/subtract immediate
     *  MOV Rd, #Offset8
     *  CMP Rd, #Offset8
     *  ADD Rd, #Offset8
     *  SUB Rd, #Offset8
     */
    else if((instr & 0xe000) == 0x2000) {
        uint8_t op      = (instr & 0x1800) >> 11;
        uint8_t rd      = (instr & 0x0700) >>  8;
        uint8_t offset8 = (instr & 0x00ff);

        switch(op) {
        case 0: /* MOV */
            reg_data[rd].v = offset8;
            reg_data[rd].o = REG_VAL_OTHER;
            break;

        case 1: /* CMP */
            /* Irrelevant to unwinding */
            break;

        case 2: /* ADD */
            chk_loaded(rd);
            reg_data[rd].v += offset8;
            reg_data[rd].o = reg_data[rd].o ? REG_VAL_OTHER : 0;
            break;

        case 3: /* SUB */
            chk_loaded(rd);
            reg_data[rd].v -= offset8;
            reg_data[rd].o = reg_data[rd].o ? REG_VAL_OTHER : 0;
            break;
        }
    }
    /* Format 4: ALU operations
     *  AND Rd, Rs
     *  EOR Rd, Rs
     *  LSL Rd, Rs
     *  LSR Rd, Rs
     *  ASR Rd, Rs
     *  ADC Rd, Rs
     *  SBC Rd, Rs
     *  ROR Rd, Rs
     *  TST Rd, Rs
     *  NEG Rd, Rs
     *  CMP Rd, Rs
     *  CMN Rd, Rs
     *  ORR Rd, Rs
     *  MUL Rd, Rs
     *  BIC Rd, Rs
     *  MVN Rd, Rs
     */
    else if ((instr & 0xfc00) == 0x4000) {
        uint32_t op = (instr & 0x03c0) >> 6;
        uint32_t rs = (instr & 0x0038) >> 3;
        uint32_t rd = (instr & 0x0007);

        /* Propagate data origins */
        switch (op) {
        case 0: /* AND */
        case 1: /* EOR */
        case 2: /* LSL */
        case 3: /* LSR */
        case 4: /* ASR */
        case 7: /* ROR */
        case 12: /* ORR */
        case 13: /* MUL */
        case 14: /* BIC */
            chk_loaded(rd);
            chk_loaded(rs);
            if (reg_data[rd].o && reg_data[rs].o) {
                reg_data[rd].o = REG_VAL_OTHER;
            }
            else {
                reg_data[rd].o = 0;
            }
            break;

        case 5: /* ADC */
        case 6: /* SBC */
            /* C-bit not tracked */
            reg_data[rd].o = 0;
            break;

        case 8: /* TST */
        case 10: /* CMP */
        case 11: /* CMN */
            /* Nothing propagated */
            break;

        case 9: /* NEG */
        case 15: /* MVN */
            chk_loaded(rs);
            reg_data[rd].o = reg_data[rs].o ? REG_VAL_OTHER : 0;
            break;
        }

        /* Perform operation */
        switch (op) {
        case 0: /* AND */
            reg_data[rd].v &= reg_data[rs].v;
            break;

        case 1: /* EOR */
            reg_data[rd].v ^= reg_data[rs].v;
            break;

        case 2: /* LSL */
            reg_data[rd].v <<= reg_data[rs].v;
            break;

        case 3: /* LSR */
            reg_data[rd].v >>= reg_data[rs].v;
            break;

        case 4: /* ASR */
            if (reg_data[rd].v & 0x80000000) {
                reg_data[rd].v >>= reg_data[rs].v;
                reg_data[rd].v |= 0xffffffff << (32 - reg_data[rs].v);
            }
            else {
                reg_data[rd].v >>= reg_data[rs].v;
            }
            break;

        case 5: /* ADC */
        case 6: /* SBC */
        case 8: /* TST */
        case 10: /* CMP */
        case 11: /* CMN */
            break;

        case 7: /* ROR */
            reg_data[rd].v = (reg_data[rd].v >> reg_data[rs].v) |
                            (reg_data[rd].v << (32 - reg_data[rs].v));
            break;

        case 9: /* NEG */
            reg_data[rd].v = ~reg_data[rs].v + 1;
            break;

        case 12: /* ORR */
            reg_data[rd].v |= reg_data[rs].v;
            break;

        case 13: /* MUL */
            reg_data[rd].v *= reg_data[rs].v;
            break;

        case 14: /* BIC */
            reg_data[rd].v &= !reg_data[rs].v;
            break;

        case 15: /* MVN */
            reg_data[rd].v = !reg_data[rs].v;
            break;
        }
    }
    /* Format 5: Hi register operations/branch exchange
     *  ADD Rd, Hs
     *  ADD Hd, Rs
     *  ADD Hd, Hs
     */
    else if ((instr & 0xfc00) == 0x4400) {
        uint8_t op = (instr & 0x0300) >> 8;
        int h1 = (instr & 0x0080) != 0;
        int h2 = (instr & 0x0040) != 0;
        uint8_t rhs = (instr & 0x0038) >> 3;
        uint8_t rhd = (instr & 0x0007);

        /* Adjust the register numbers */
        if (h2) rhs += 8;
        if (h1) rhd += 8;

        if (op != 3 && !h1 && !h2) {
            set_errno(ERR_OTHER, "h1 or h2 must be set for ADD, CMP or MOV");
            return -1;
        }

        switch (op) {
        case 0: /* ADD */
            chk_loaded(rhd);
            chk_loaded(rhs);
            reg_data[rhd].v += reg_data[rhs].v;
            reg_data[rhd].o = reg_data[rhd].o && reg_data[rhs].o ? REG_VAL_OTHER : 0;
            break;

        case 1: /* CMP */
            /* Irrelevant to unwinding */
            break;

        case 2: /* MOV */
            chk_loaded(rhs);
            reg_data[rhd].v += reg_data[rhs].v;
            reg_data[rhd].o  = reg_data[rhd].o;
            break;

        case 3: /* BX */
            /* Only follow BX if the data was from the stack */
            if (reg_data[rhs].o == REG_VAL_STACK) {
                /* Update the PC */
                chk_loaded(rhs);
                reg_data[15] = reg_data[rhs];
                if (reg_data[rhs].v & 0x1) {
                    /* Account for the auto-increment which isn't needed */
                    reg_data[15].v -= 2;
                }
                trace_return = 1;
            }
            else {
                set_fmt_errno(ERR_OTHER, "BX to invalid register: r%d", rhs);
                return -1;
            }
        }
    }
    /* Format 9: PC-relative load
     *  LDR Rd,[PC, #imm]
     */
    else if ((instr & 0xf800) == 0x4800) {
        uint8_t  rd    = (instr & 0x0700) >> 8;
        uint8_t  word8 = (instr & 0x00ff);

        /* Compute load address, adding a word to account for prefetch */
        load_reg_lazy((reg_data[15].v & (~0x3)) + 4 + (word8 << 2), rd);
    }
    /* Format 13: add offset to Stack Pointer
     *  ADD sp,#+imm
     *  ADD sp,#-imm
     */
    else if ((instr & 0xff00) == 0xB000) {
        uint8_t value = (instr & 0x7f) * 4;

        chk_loaded(13);
        /* Check the negative bit */
        if (instr & 0x80) {
            reg_data[13].v -= value;
        }
        else {
            reg_data[13].v += value;
        }
    }
    /* Format 14: push/pop registers
     *  PUSH {Rlist}
     *  PUSH {Rlist, LR}
     *  POP {Rlist}
     *  POP {Rlist, PC}
     */
    else if ((instr & 0xf600) == 0xb400) {
        int  L = (instr & 0x0800) != 0;
        int  R = (instr & 0x0100) != 0;
        uint8_t rList = (instr & 0x00ff);

        chk_loaded(13);

        if (L) {
            int r;

            /* Load from memory: POP */
            for (r = 0; r < 8; r++) {
                if (rList & (0x1 << r)) {
                    /* Read the word */
                    if (reg_data[13].o) {
                        reg_data[r].o = REG_VAL_STACK;
                        reg_data[r].v = reg_data[13].v;
                        reg_data[13].v += 4;
                    }
                    else {
                        reg_data[r].o = 0;
                    }
                }
            }

            /* Check if the PC is to be popped */
            if (R) {
                /* Get the return address */
                if (load_reg(reg_data[13].v, 15) < 0) return -1;
                if (!reg_data[15].o) {
                    /* Return address is not valid */
                    set_errno(ERR_OTHER, "PC popped with invalid address");
                    return -1;
                }

                /* The bottom bit should have been set to indicate that
                 *  the caller was from Thumb.  This would allow return
                 *  by BX for interworking APCS.
                 */
                if ((reg_data[15].v & 0x1) == 0) {
                    /* Pop into the PC will not switch mode */
                    set_fmt_errno(ERR_OTHER, "Return address not to Thumb: 0x%08x", reg_data[15].v);
                    return -1;
                }

                /* Update the sp */
                reg_data[13].v += 4;

                /* Compensate for the auto-increment, which isn't needed here */
                reg_data[15].v -= 2;

                /* Report the return address */
                trace_return = 1;
            }
        }
        else {
            int r;

            /* Check if the LR is to be pushed */
            if (R) {
                reg_data[13].v -= 4;
                if (store_reg(reg_data[13].v, 14) < 0) return -1;
            }

            for (r = 7; r >= 0; r--) {
                if (rList & (0x1 << r)) {
                    reg_data[13].v -= 4;
                    if (store_reg(reg_data[13].v, r) < 0) return -1;
                }
            }
        }
    }
    /* Format 18: unconditional branch
     *  B label
     */
    else if ((instr & 0xf800) == 0xe000) {
        uint32_t addr = instr & 0x07ff;
        if (addr & 0x400) addr |= 0xf800;
        addr = reg_data[15].v + addr * 2 + 2;
        add_branch(addr);
        trace_branch = 1;
    }
    else {
        /* Unknown/undecoded.  May alter some register, so invalidate file */
        unsigned i;
        for (i = 0; i < 13; i++) reg_data[i].o = 0;
    }

    if (!trace_return && !trace_branch) {
        /* Check next address */
        reg_data[15].v += 2;
    }
    return 0;
}

static int trace_jazelle(void) {
    set_errno(ERR_OTHER, "Jazelle is not supported yet");
    return -1;
}

/* Check if some instruction is a data-processing instruction */
static int is_data_processing_instr(uint32_t instr) {
    uint32_t opcode = (instr & 0x01e00000) >> 21;
    int S = (instr & 0x00100000) != 0;

    if ((instr & 0x0c000000) != 0x00000000) return 0;
    if ((instr & 0xf0000000) == 0xf0000000) return 0;
    if (!S && opcode >= 8 && opcode <= 11) return 0;
    return 1;
}

static int trace_arm_bx(uint32_t instr) {
    uint8_t rn = instr & 0xf;

    if (!reg_data[rn].o) {
        set_errno(ERR_OTHER, "BX to untracked register");
        return -1;
    }

    /* Set the new PC value */
    reg_data[15] = reg_data[rn];
    chk_loaded(15);

    /* Determine the new mode */
    if (reg_data[15].o && reg_data[15].v & 0x1u) {
        /* Branch to THUMB */
        cpsr_data.v |= 0x00000020;
        reg_data[15].v &= ~0x1u;
    }

    /* Check if the return value is from the stack */
    if (rn == 14 || reg_data[rn].o == REG_VAL_STACK) {
        /* Found the return address */
        trace_return = 1;
    }
    return 0;
}

static void trace_arm_branch_instruction(uint32_t instr) {
    uint32_t addr = reg_data[15].v;
    uint32_t offset = (instr & 0x00ffffff) << 2;
    if (offset & 0x02000000) offset |= 0xfc000000;
    addr += offset + 8;

    add_branch(addr);

    if ((instr & 0xf0000000) == 0xe0000000) {
        /* Unconditional branch */
        trace_branch = 1;
    }
}

static void trace_arm_mrs_msr(uint32_t instr) {
    uint32_t cond = (instr >> 28) & 0xf;
    if (instr & (1 << 21)) {
        uint8_t rn = instr & 0xf;
        if (instr & (1 << 22)) {
            /* SPSR is not traced */
        }
        else if (cond != 14) {
            cpsr_data.o = 0;
        }
        else {
            uint32_t mask = 0;
            if (instr & (1 << 19)) mask |= 0xff000000;
            if (instr & (1 << 18)) mask |= 0x00ff0000;
            if (instr & (1 << 17)) mask |= 0x0000ff00;
            if (instr & (1 << 16)) mask |= 0x000000ff;
            if (mask) {
                chk_loaded(rn);
                if (!reg_data[rn].o) {
                    cpsr_data.o = 0;
                }
                else {
                    cpsr_data.v &= ~mask;
                    cpsr_data.v |= reg_data[rn].v & mask;
                    cpsr_data.o = REG_VAL_OTHER;
                }
            }
        }
    }
    else {
        uint8_t rd = (instr & 0x0000f000) >> 12;
        if (instr & (1 << 22)) {
            reg_data[rd].o = 0;
        }
        else if (cond != 14) {
            reg_data[rd].o = 0;
        }
        else {
            reg_data[rd] = cpsr_data;
        }
    }
}

static void trace_arm_cps(uint32_t instr) {
    if (instr & (1 << 17)) {
        uint32_t m0 = cpsr_data.v & ~0x1f;
        uint32_t m1 = instr & 0x1f;
        if (m0 != m1) {
            unsigned i;
            if (m0 == 0x11 || m1 == 0x11) {
                for (i = 8; i < 15; i++) reg_data[i].o = 0;
            }
            else if ((m0 >= 0x12 && m0 < 0x1b) || (m1 >= 0x12 && m1 <= 0x1b)) {
                for (i = 13; i < 15; i++) reg_data[i].o = 0;
            }
            cpsr_data.v = (cpsr_data.v & ~m0) | m1;
        }
    }
}

static void trace_arm_ldr_str(uint32_t instr) {
    uint32_t cond = (instr >> 28) & 0xf;
    int I = (instr & (1 << 25)) != 0;
    int P = (instr & (1 << 24)) != 0;
    int U = (instr & (1 << 23)) != 0;
    int B = (instr & (1 << 22)) != 0;
    int W = (instr & (1 << 21)) != 0;
    int L = (instr & (1 << 20)) != 0;
    uint32_t rn = (instr & 0x000f0000) >> 16;
    uint32_t rd = (instr & 0x0000f000) >> 12;
    uint32_t adr = 0;

    chk_loaded(rn);
    adr = reg_data[rn].v;

    if (rn == 15) adr += 8;

    if (B || cond != 14 || !reg_data[rn].o) {
        if (L) reg_data[rd].o = 0;
    }
    else if (!I && P) {
        uint32_t offs = instr & 0xfff;
        adr = U ? adr + offs : adr - offs;
        if (W) reg_data[rn].v = adr;
        if (L) load_reg_lazy(adr, rd);
        else store_reg(adr, rd);
    }
    else if (I && P) {
        uint8_t rm = instr & 0xf;
        chk_loaded(rm);
        if (!reg_data[rm].o) {
            if (L) reg_data[rd].o = 0;
            if (W) reg_data[rn].o = 0;
        }
        else if ((instr & 0x00000ff0) == 0x00000000) {
            adr = U ? adr + reg_data[rm].v : adr - reg_data[rm].v;
            if (W) reg_data[rn].v = adr;
            if (L) load_reg_lazy(adr, rd);
            else store_reg(adr, rd);
        }
        else {
            uint32_t shift_imm = (instr & 0x00000f80) >> 7;
            uint32_t shift_type = (instr & 0x00000060) >> 5;
            uint32_t val = calc_shift(shift_type, shift_imm, reg_data[rm].v);
            adr = U ? adr + val : adr - val;
            if (W) reg_data[rn].v = adr;
            if (L) load_reg_lazy(adr, rd);
            else store_reg(adr, rd);
        }
    }
    else if (!I && !P && !W) {
        uint32_t offs = instr & 0xfff;
        if (L) load_reg_lazy(adr, rd);
        else store_reg(adr, rd);
        adr = U ? adr + offs : adr - offs;
        reg_data[rn].v = adr;
    }
    else if (I && !P && !W) {
        uint8_t rm = instr & 0xf;
        chk_loaded(rm);
        if (!reg_data[rm].o) {
            if (L) reg_data[rd].o = 0;
            reg_data[rn].o = 0;
        }
        else if ((instr & 0x00000ff0) == 0x00000000) {
            if (L) load_reg_lazy(adr, rd);
            else store_reg(adr, rd);
            adr = U ? adr + reg_data[rm].v : adr - reg_data[rm].v;
            reg_data[rn].v = adr;
        }
        else {
            uint32_t shift_imm = (instr & 0x00000f80) >> 7;
            uint32_t shift_type = (instr & 0x00000060) >> 5;
            uint32_t val = 0;
            chk_loaded(rm);
            val = calc_shift(shift_type, shift_imm, reg_data[rm].v);
            if (L) load_reg_lazy(adr, rd);
            else store_reg(adr, rd);
            adr = U ? adr + val : adr - val;
            reg_data[rn].v = adr;
        }
    }
    else if (L) {
        reg_data[rd].o = 0;
    }
    if (rd == 15 && rn == 13 && !I && !P && !W) { /* pop {pc} */
        /* Found the return instruction */
        trace_return = 1;
    }
}

static void trace_arm_extra_ldr_str(uint32_t instr) {
    /* Extra load/store instructions */
    uint32_t cond = (instr >> 28) & 0xf;
    int T = (instr & (1 << 24)) == 0 && (instr & (1 << 21));
    uint32_t op2 = (instr >> 5) & 3;
    uint32_t rd = (instr >> 12) & 0xf;
    int L =  op2 == 2 || (instr & (1 << 20));
    int P = (instr & (1 << 24)) != 0;
    int U = (instr & (1 << 23)) != 0;
    int W = (instr & (1 << 21)) != 0;
    int size = 0;
    int sign = 0;
    uint32_t addr = 0;
    int ok = 1;

    if (op2 == 1) {
        /* halfword */
        size = 2;
    }
    else if (instr & (1 << 20)) {
        /* signed byte and halfword */
        size = op2 == 2 ? 1 : 2;
        sign = 1;
    }
    else {
        size = 8;
        T = 0;
    }

    if (cond != 14 || size != 8 || sign || T) {
        /* May be next time */
        ok = 0;
    }
    else if (instr & (1 << 22)) {
        uint32_t rn = (instr >> 16) & 0xf;
        uint32_t imm8 = ((instr >> 4) & 0xf0) | (instr & 0x0f);
        chk_loaded(rn);
        if (reg_data[rn].o == 0) {
            ok = 0;
        }
        else if (P) {
            addr = reg_data[rn].v;
            addr = U ? addr + imm8 : addr - imm8;
            if (W) {
                reg_data[rn].o = REG_VAL_OTHER;
                reg_data[rn].v = addr;
            }
        }
        else {
            addr = reg_data[rn].v;
            reg_data[rn].v = U ? addr + imm8 : addr - imm8;
        }
    }
    else {
        uint32_t rn = (instr >> 16) & 0xf;
        uint32_t rm = instr & 0xf;
        uint32_t offs = reg_data[rm].v;
        chk_loaded(rn);
        chk_loaded(rm);
        if (reg_data[rn].o == 0 || reg_data[rm].o == 0) {
            ok = 0;
        }
        else if (P) {
            addr = reg_data[rn].v;
            addr = U ? addr + offs : addr - offs;
            if (W) reg_data[rn].v = addr;
        }
        else {
            addr = reg_data[rn].v;
            reg_data[rn].v = U ? addr + offs : addr - offs;
        }
    }

    if (ok && L) {
        load_reg_lazy(addr, rd);
        if (size == 8) load_reg_lazy(addr + 4, (rd + 1) & 0xf);
    }
    else if (ok) {
        store_reg(addr, rd);
        if (size == 8) store_reg(addr + 4, (rd + 1) & 0xf);
    }
    else if (L) {
        reg_data[rd].o = 0;
        if (size == 8) reg_data[(rd + 1) & 0xf].o = 0;
    }
}

static void trace_arm_data_processing_instr(uint32_t instr) {
    uint32_t cond = (instr >> 28) & 0xf;
    int I = (instr & 0x02000000) != 0;
    uint32_t opcode = (instr & 0x01e00000) >> 21;
    uint32_t rn = (instr & 0x000f0000) >> 16;
    uint32_t rd = (instr & 0x0000f000) >> 12;
    uint32_t operand2 = (instr & 0x00000fff);
    uint32_t op2val = 0;
    uint32_t op2origin = 0;

    /* Decode operand 2 */
    if (I) {
        uint8_t shift_dist  = (operand2 & 0x0f00) >> 8;
        uint8_t shift_const = (operand2 & 0x00ff);

        /* rotate const right by 2 * shift_dist */
        shift_dist *= 2;
        op2val    = (shift_const >> shift_dist) |
                    (shift_const << (32 - shift_dist));
        op2origin = REG_VAL_OTHER;
    }
    else {
        /* Register and shift */
        uint8_t rm = (operand2 & 0x000f);
        uint8_t reg_shift = (operand2 & 0x0010) != 0;
        uint8_t shift_type = (operand2 & 0x0060) >> 5;
        uint32_t shift_dist = 0;

        /* Get the shift distance */
        if (reg_shift) {
            uint8_t rs = (operand2 & 0x0f00) >> 8;
            if (operand2 & 0x00800) {
                op2origin = 0;
            }
            else if (rs == 15) {
                op2origin = 0;
            }
            else {
                chk_loaded(rs);
                shift_dist = reg_data[rs].v;
                op2origin = reg_data[rs].o;
            }
        }
        else {
            shift_dist  = (operand2 & 0x0f80) >> 7;
            op2origin = REG_VAL_OTHER;
        }

        if (!op2origin) {
            op2val = 0;
        }
        else if (shift_type == 0 && shift_dist == 0 && opcode == 13) {
            /* MOV rd,rm */
            op2origin = reg_data[rm].o;
            op2val = reg_data[rm].v;
        }
        else {
            /* Apply the shift type to the source register */
            chk_loaded(rm);
            switch (shift_type) {
            case 0: /* logical left */
                op2val = reg_data[rm].v << shift_dist;
                break;
            case 1: /* logical right */
                if (!reg_shift && shift_dist == 0) shift_dist = 32;
                op2val = reg_data[rm].v >> shift_dist;
                break;
            case 2: /* arithmetic right */
                if (!reg_shift && shift_dist == 0) shift_dist = 32;
                if (reg_data[rm].v & 0x80000000) {
                    /* Register shifts maybe greater than 32 */
                    if (shift_dist >= 32) {
                        op2val = 0xffffffff;
                    }
                    else {
                        op2val = reg_data[rm].v >> shift_dist;
                        op2val |= 0xffffffff << (32 - shift_dist);
                    }
                }
                else {
                    op2val = reg_data[rm].v >> shift_dist;
                }
                break;
            case 3: /* rotate right */
                if (!reg_shift && shift_dist == 0) {
                    /* Rotate right with extend.
                     *  This uses the carry bit and so always has an
                     *  untracked result.
                     */
                    op2origin = 0;
                    op2val = 0;
                }
                else {
                    /* Limit shift distance to 0-31 incase of register shift */
                    shift_dist &= 0x1f;
                    op2val = (reg_data[rm].v >> shift_dist) |
                             (reg_data[rm].v << (32 - shift_dist));
                }
                break;
            }

            /* Decide the data origin */
            op2origin = reg_data[rm].o ? REG_VAL_OTHER : 0;
        }
    }

    if (rd == 15 && cond != 14) {
        /* Conditional branch, trace both directions */
        if (op2origin) {
            if (opcode == 13) {
                add_branch(op2val);
            }
            else if (opcode == 15) {
                add_branch(~op2val);
            }
            else if (reg_data[rn].o) {
                switch (opcode) {
                case  0: add_branch(reg_data[rn].v & op2val); break;
                case  1: add_branch(reg_data[rn].v ^ op2val); break;
                case  2: add_branch(reg_data[rn].v - op2val); break;
                case  3: add_branch(op2val - reg_data[rn].v); break;
                case  4: add_branch(reg_data[rn].v + op2val); break;
                case 12: add_branch(reg_data[rn].v | op2val); break;
                case 14: add_branch(reg_data[rn].v & ~op2val); break;
                }
            }
        }
        return;
    }

    /* Propagate register validity */
    switch (opcode) {
    case  0: /* AND: Rd:= Op1 AND Op2 */
    case  1: /* EOR: Rd:= Op1 EOR Op2 */
    case  2: /* SUB: Rd:= Op1 - Op2 */
    case  3: /* RSB: Rd:= Op2 - Op1 */
    case  4: /* ADD: Rd:= Op1 + Op2 */
    case 12: /* ORR: Rd:= Op1 OR Op2 */
    case 14: /* BIC: Rd:= Op1 AND NOT Op2 */
        chk_loaded(rn);
        if (reg_data[rn].o && op2origin && cond == 14) {
            reg_data[rd].o = REG_VAL_OTHER;
        }
        else {
            reg_data[rd].o = 0;
        }
        break;
    case  5: /* ADC: Rd:= Op1 + Op2 + C */
    case  6: /* SBC: Rd:= Op1 - Op2 + C */
    case  7: /* RSC: Rd:= Op2 - Op1 + C */
        /* CPSR is not tracked */
        reg_data[rd].o = 0;
        break;
    case  8: /* TST: set condition codes on Op1 AND Op2 */
    case  9: /* TEQ: set condition codes on Op1 EOR Op2 */
    case 10: /* CMP: set condition codes on Op1 - Op2 */
    case 11: /* CMN: set condition codes on Op1 + Op2 */
        break;
    case 13: /* MOV: Rd:= Op2 */
    case 15: /* MVN: Rd:= NOT Op2 */
        if (cond == 14) {
            reg_data[rd].o = op2origin;
        }
        else {
            reg_data[rd].o = 0;
        }
        break;
    }

    /* Account for pre-fetch by temporarily adjusting PC */
    if (rn == 15) {
        /* If the shift amount is specified in the instruction,
         *  the PC will be 8 bytes ahead. If a register is used
         *  to specify the shift amount the PC will be 12 bytes
         *  ahead.
         */
        if (!I && (operand2 & 0x0010))
            reg_data[rn].v += 12;
        else
            reg_data[rn].v += 8;
    }

    /* Compute values */
    switch (opcode) {
    case  0: /* AND: Rd:= Op1 AND Op2 */
        reg_data[rd].v = reg_data[rn].v & op2val;
        break;
    case  1: /* EOR: Rd:= Op1 EOR Op2 */
        reg_data[rd].v = reg_data[rn].v ^ op2val;
        break;
    case  2: /* SUB: Rd:= Op1 - Op2 */
        reg_data[rd].v = reg_data[rn].v - op2val;
        break;
    case  3: /* RSB: Rd:= Op2 - Op1 */
        reg_data[rd].v = op2val - reg_data[rn].v;
        break;
    case  4: /* ADD: Rd:= Op1 + Op2 */
        reg_data[rd].v = reg_data[rn].v + op2val;
        break;
    case  5: /* ADC: Rd:= Op1 + Op2 + C */
    case  6: /* SBC: Rd:= Op1 - Op2 + C */
    case  7: /* RSC: Rd:= Op2 - Op1 + C */
    case  8: /* TST: set condition codes on Op1 AND Op2 */
    case  9: /* TEQ: set condition codes on Op1 EOR Op2 */
    case 10: /* CMP: set condition codes on Op1 - Op2 */
    case 11: /* CMN: set condition codes on Op1 + Op2 */
        break;
    case 12: /* ORR: Rd:= Op1 OR Op2 */
        reg_data[rd].v = reg_data[rn].v | op2val;
        break;
    case 13: /* MOV: Rd:= Op2 */
        reg_data[rd].v = op2val;
        break;
    case 14: /* BIC: Rd:= Op1 AND NOT Op2 */
        reg_data[rd].v = reg_data[rn].v & (~op2val);
        break;
    case 15: /* MVN: Rd:= NOT Op2 */
        reg_data[rd].v = ~op2val;
        break;
    }

    if (rd == 15 && !I && !(operand2 & 0x0f90) && (operand2 & 0x000f) == 14 && op2origin) {
        /* move pc, lr - return */
        trace_return = 1;
    }

    /* Remove the prefetch offset from the PC */
    if (rd != 15 && rn == 15) {
        if (!I && (operand2 & 0x0010))
            reg_data[rn].v -= 12;
        else
            reg_data[rn].v -= 8;
    }
}

static int trace_arm_ldm_stm(uint32_t instr) {
    int P = (instr & 0x01000000) != 0;
    int U = (instr & 0x00800000) != 0;
    int S = (instr & 0x00400000) != 0;
    int W = (instr & 0x00200000) != 0;
    int L = (instr & 0x00100000) != 0;
    uint16_t rn = (instr & 0x000f0000) >> 16;
    uint16_t regs = (instr & 0x0000ffff);
    uint32_t addr = 0;
    int addr_valid = 0;
    uint8_t r;

    chk_loaded(rn);
    addr = reg_data[rn].v;
    addr_valid = reg_data[rn].o != 0;

    /* S indicates that banked registers (untracked) are used, unless
     *  this is a load including the PC when the S-bit indicates that
     *  that CPSR is loaded from SPSR (also untracked, but ignored).
     */
    if (S && (!L || (regs & (1 << 15)) == 0)) {
        set_errno(ERR_OTHER, "S-bit set requiring banked registers");
        return -1;
    }
    if (rn == 15) {
        set_errno(ERR_OTHER, "r15 used as base register");
        return -1;
    }

    /* Check if ascending or descending.
     *  Registers are loaded/stored in order of address.
     *  i.e. r0 is at the lowest address, r15 at the highest.
     */
    r = U ? 0 : 15;

    for (;;) {
        /* Check if the register is to be transferred */
        if (regs & (1 << r)) {
            if (P) addr = U ? addr + 4 : addr - 4;
            if (L) {
                if (addr_valid) {
                    reg_data[r].o = rn == 13 ? REG_VAL_STACK : REG_VAL_ADDR;
                    reg_data[r].v = addr;
                }
                else {
                    /* Invalidate the register as the base reg was invalid */
                    reg_data[r].o = 0;
                }
            }
            else if (addr_valid) {
                store_reg(addr, r);
            }
            if (!P) addr = U ? addr + 4 : addr - 4;
        }
        /* Check the next register */
        if (U) {
            if (r == 15) break;
            r++;
        }
        else {
            if (r == 0) break;
            r--;
        }
    }

    /* Check the writeback bit */
    if (addr_valid && W) reg_data[rn].v = addr;

    /* Check if the PC was loaded */
    if (L && (regs & (1 << 15))) {
        if (!reg_data[15].o) {
            /* Return address is not valid */
            set_errno(ERR_OTHER, "PC popped with invalid address");
            return -1;
        }
        /* Found the return address */
        trace_return = 1;
    }
    return 0;
}

static void trace_arm_16bit_imm(uint32_t instr) {
    uint32_t rd = (instr >> 12) & 0xf;
    uint32_t cond = (instr >> 28) & 0xf;
    if (cond != 14) {
        reg_data[rd].o = 0;
    }
    else {
        uint32_t imm = (instr & 0xfff) | ((instr & 0xf0000) >> 4);
        if (instr & (1 << 22)) { /* MOVT */
            chk_loaded(rd);
            if (reg_data[rd].o) {
                imm = (reg_data[rd].v & 0xffff) | (imm << 16);
                reg_data[rd].o = REG_VAL_OTHER;
                reg_data[rd].v = imm;
            }
        }
        else { /* MOVW */
            if (imm & 0x8000) imm |= 0xffff0000;
            reg_data[rd].o = REG_VAL_OTHER;
            reg_data[rd].v = imm;
        }
    }
}

static void trace_coprocessor_instr(uint32_t instr) {
    uint32_t cond = (instr >> 28) & 0xf;
    unsigned i;

    if (cond != 15 && (instr & 0x0f000e10) == 0x0e000a00) {
        /* VFP data processing */
        return;
    }

    if ((instr & 0x0e000000) == 0x0c000000) {
        int P = (instr & (1 << 24)) != 0;
        int U = (instr & (1 << 23)) != 0;
        int D = (instr & (1 << 22)) != 0;
        int W = (instr & (1 << 21)) != 0;
        int L = (instr & (1 << 20)) != 0;
        if ((instr & 0x00000e00) == 0x00000a00) {
            uint32_t rn = (instr >> 16) & 0xf;
            if (!P && !U && !W) {
                if (D && (instr & 0x000000d0) == 0x00000010) {
                    /* 64-bit transfers between ARM core and extension registers */
                    if (L) {
                        reg_data[(instr >> 12) & 0xf].o = 0;
                        reg_data[(instr >> 16) & 0xf].o = 0;
                    }
                    return;
                }
            }
            else if (P && !W) {
                /* vldr, vstr */
                return;
            }
            else if (P == U && W) {
                /* Undefined */
            }
            else {
                /* vldm, vstm */
                uint32_t imm8 = instr & 0xff;
                if (W && reg_data[rn].o) {
                    if (cond != 14) {
                        reg_data[rn].o = 0;
                        return;
                    }
                    chk_loaded(rn);
                    if (U) {
                        reg_data[rn].v += imm8 * 4;
                    }
                    else {
                        reg_data[rn].v -= imm8 * 4;
                    }
                    reg_data[rn].o = REG_VAL_OTHER;
                }
                return;
            }
        }
        else if (!P && !U && D && !W) {
            /* mrrc, mcrr */
            if (L) {
                reg_data[(instr >> 12) & 0xf].o = 0;
                reg_data[(instr >> 16) & 0xf].o = 0;
            }
            return;
        }
        else if (!P && !U && !D && !W) {
            /* Undefined */
        }
        else {
            /* ldc, stc */
            if (W) reg_data[(instr >> 16) & 0xf].o = 0;
            return;
        }
    }

    if ((instr & 0x0fe00f90) == 0x0ee00a10) { /* VMRS/VMSR */
        int A = (instr & (1 << 20)) != 0;
        if (A) reg_data[(instr >> 12) & 0xf].o = 0;
        return;
    }

    if ((instr & 0x0f900f10) == 0x0e000b10) { /* VMOV.sz Dn, Rn */
        return;
    }

    if ((instr & 0x0f100f10) == 0x0e100b10) { /* VMOV.sz Rn, Dn */
        reg_data[(instr >> 12) & 0xf].o = 0;
        return;
    }

    if ((instr & 0x0fe00f10) == 0x0e000a10) { /* VMOV Sn */
        int L = (instr & (1 << 20)) != 0;
        if (L) reg_data[(instr >> 12) & 0xf].o = 0;
        return;
    }

    if ((instr & 0x0f000010) == 0x0e000010) { /* MRC, MCR */
        int A = (instr & (1 << 20)) != 0;
        if (A) reg_data[(instr >> 12) & 0xf].o = 0;
        return;
    }

    if ((instr & 0x0f000010) == 0x0e000000) { /* CDP */
        return;
    }

    /* Unknown/undecoded.  May alter some register, so invalidate file */
    for (i = 0; i < 13; i++) reg_data[i].o = 0;
}

static int trace_arm(void) {
    uint32_t instr;

    assert(reg_data[15].o != REG_VAL_ADDR);
    assert(reg_data[15].o != REG_VAL_STACK);

    /* Check that the PC is still on Arm alignment */
    if (reg_data[15].v & 0x3) {
        set_errno(ERR_OTHER, "PC misalignment");
        return -1;
    }

    /* Read the instruction */
    if (read_word(reg_data[15].v, &instr) < 0) return -1;

    if ((instr & 0xfffffff0) == 0xe12fff10) {
        /* Branch and Exchange (BX)
         *  This is tested prior to data processing to prevent
         *  mis-interpretation as an invalid TEQ instruction.
         */
        if (trace_arm_bx(instr) < 0) return -1;
    }
    else if ((instr & 0x0f000000) == 0x0a000000) { /* Branch */
        trace_arm_branch_instruction(instr);
    }
    else if ((instr & 0x0f000000) == 0x0b000000) { /* BL */
        /* Subroutines are expected to preserve the contents of r4 to r11 and r13 */
        unsigned i;
        for (i = 0; i <= 14; i++) {
            if (i >= 4 && i <= 11) continue;
            if (i == 13) continue;
            reg_data[i].o = 0;
        }
    }
    else if ((instr & 0x0f9000f0) == 0x01000000) { /* MRS, MSR */
        trace_arm_mrs_msr(instr);
    }
    else if ((instr & 0xfff10020) == 0xf1000000) { /* CPS */
        trace_arm_cps(instr);
    }
    else if ((instr & 0xfff00000) == 0xf5700000) { /* CLREX, DSB, DMB, ISB */
        /* No register changes */
    }
    else if ((instr & 0x0fff00ff) == 0x03200000) { /* NOP */
        /* No register changes */
    }
    else if ((instr & 0x0c000000) == 0x04000000) { /* LDR, STR */
        trace_arm_ldr_str(instr);
    }
    else if ((instr & 0x0fb000f0) == 0x01000090) { /* SWP, SWPB */
        reg_data[(instr >> 12) & 0xf].o = 0;
    }
    else if ((instr & 0x0f8000f0) == 0x01800090) { /* LDREX, STREX */
        int L = (instr & (1 << 20)) != 0;
        if (L) {
            int op = (instr >> 21) & 3;
            reg_data[(instr >> 12) & 0xf].o = 0;
            if (op == 1) reg_data[((instr >> 12) + 1) & 0xf].o = 0;
        }
    }
    else if ((instr & 0x0e0000f0) == 0x00000090) { /* MUL, ... */
        reg_data[(instr >> 16) & 0xf].o = 0;
    }
    else if ((instr & 0x0e000090) == 0x00000090) {
        trace_arm_extra_ldr_str(instr);
    }
    else if (is_data_processing_instr(instr)) { /* Data processing */
        trace_arm_data_processing_instr(instr);
    }
    else if ((instr & 0xfe000000) == 0xe8000000) { /* Block Data Transfer - LDM, STM */
        if (trace_arm_ldm_stm(instr) < 0) return -1;
    }
    else if ((instr & 0x0fb00000) == 0x03000000) { /* 16-bit immediate load */
        trace_arm_16bit_imm(instr);
    }
    else if ((instr & 0x0ff000f0) == 0x01600010) { /* CLZ - Count Leading Zeros */
        reg_data[(instr >> 12) & 0xf].o = 0;;
    }
    else if ((instr & 0x0c000000) == 0x0c000000) {
        trace_coprocessor_instr(instr);
    }
    else {
        unsigned i;
        /* Unknown/undecoded.  May alter some register, so invalidate file */
        for (i = 0; i < 13; i++) reg_data[i].o = 0;
    }

    if (!trace_return && !trace_branch) {
        /* Check next address */
        reg_data[15].v += 4;
    }
    return 0;
}

static int trace_instructions(void) {
    unsigned i;
    RegData org_sp = reg_data[13];
    RegData org_lr = reg_data[14];
    for (;;) {
        unsigned t = 0;
        BranchData * b = NULL;
        uint32_t sp = 0;
        if (chk_loaded(13) < 0) return -1;
        if (chk_loaded(15) < 0) return -1;
        sp = reg_data[13].v;
        trace(LOG_STACK, "Stack crawl: pc 0x%08x, sp 0x%08x",
            reg_data[15].o ? reg_data[15].v : 0,
            reg_data[13].o ? reg_data[13].v : 0);
        for (t = 0; t < 200; t++) {
            int error = 0;
            trace_return = 0;
            trace_branch = 0;
            if (chk_loaded(15) < 0) {
                error = errno;
            }
            else if (!reg_data[15].o) {
                error = set_errno(ERR_OTHER, "PC value not available");
            }
            else if (!reg_data[15].v) {
                error = set_errno(ERR_OTHER, "PC == 0");
            }
            else if (!cpsr_data.o) {
                error = set_errno(ERR_OTHER, "CPSR value not available");
            }
            else {
                int r = 0;
                if (cpsr_data.v & 0x01000000) r = trace_jazelle();
                else if (cpsr_data.v & 0x00000020) r = trace_thumb();
                else r = trace_arm();
                if (r < 0) error = errno;
            }
            if (!error && trace_return) {
                if (chk_loaded(13) < 0 || !reg_data[13].o || reg_data[13].v < sp) {
                    error = set_errno(ERR_OTHER, "Stack crawl: invalid SP value");
                }
            }
            if (error) {
                trace(LOG_STACK, "Stack crawl: %s", errno_to_str(error));
                break;
            }
            if (trace_return) return 0;
            if (trace_branch) break;
#if 0  /* TODO: mem hash cleanup is incorrect - it destroies hash chains */
            if (reg_data[13].o) {
                /* Remove memory hash items that point to unused stack area */
                uint16_t i;
                uint32_t sp = reg_data[13].v;
                for (i = 0; i < MEM_HASH_SIZE; i++) {
                    if (mem_data.used[i] && mem_data.a[i] < sp) {
                        mem_data.used[i] = 0;
                    }
                }
            }
#endif
        }
        if (branch_pos >= branch_cnt) break;
        b = branch_data + branch_pos++;
        mem_data = b->mem_data;
        cpsr_data = b->cpsr_data;
        memcpy(reg_data, b->reg_data, sizeof(reg_data));
    }
    trace(LOG_STACK, "Stack crawl: Function epilogue not found");
    for (i = 0; i < 16; i++) reg_data[i].o = 0;
    if (org_sp.v != 0) reg_data[13] = org_sp;
    if (org_lr.v != 0) reg_data[15] = org_lr;
    cpsr_data.o = 0;
    return 0;
}

int crawl_stack_frame_arm(StackFrame * frame, StackFrame * down) {
    RegisterDefinition * def = NULL;

#if USE_MEM_CACHE
    unsigned i;
    for (i = 0; i < MEM_CACHE_SIZE; i++) mem_cache[i].size = 0;
#endif

    stk_ctx = frame->ctx;
    memset(&cpsr_data, 0, sizeof(cpsr_data));
    memset(&reg_data, 0, sizeof(reg_data));
    memset(&mem_data, 0, sizeof(mem_data));
    branch_pos = 0;
    branch_cnt = 0;

    for (def = get_reg_definitions(stk_ctx); def->name; def++) {
        uint64_t v = 0;
        if (def->dwarf_id == 128) {
            if (read_reg_value(frame, def, &v) < 0) continue;
            cpsr_data.v = (uint32_t)v;
            cpsr_data.o = REG_VAL_OTHER;
        }
        else {
            if (def->dwarf_id < 0 || def->dwarf_id > 15) continue;
            if (read_reg_value(frame, def, &v) < 0) continue;
            reg_data[def->dwarf_id].v = (uint32_t)v;
            reg_data[def->dwarf_id].o = REG_VAL_OTHER;
        }
    }

    if (trace_instructions() < 0) return -1;

    for (def = get_reg_definitions(stk_ctx); def->name; def++) {
        if (def->dwarf_id == 128) {
            if (!cpsr_data.o) continue;
            if (write_reg_value(down, def, cpsr_data.v) < 0) return -1;
        }
        else {
            if (def->dwarf_id < 0 || def->dwarf_id > 15) continue;
            if (chk_loaded(def->dwarf_id) < 0) continue;
            if (!reg_data[def->dwarf_id].o) continue;
            if (write_reg_value(down, def, reg_data[def->dwarf_id].v) < 0) return -1;
            if (def->dwarf_id == 13) frame->fp = reg_data[def->dwarf_id].v;
        }
    }

    stk_ctx = NULL;
    return 0;
}

#endif
