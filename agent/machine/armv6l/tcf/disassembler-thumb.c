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

#include <tcf/config.h>

#include <stdio.h>
#include <assert.h>
#include <tcf/framework/context.h>
#include <machine/arm/tcf/disassembler-arm.h>

static char buf[128];
static size_t buf_pos = 0;
static uint16_t instr = 0;
static uint32_t instr_addr = 0;
static uint8_t * instr_code = NULL;
static ContextAddress instr_size = 0;
static const char * it_cond_name = NULL;
static unsigned it_cnt = 0;
static unsigned it_pos = 0;
static unsigned it_mask = 0;
static unsigned it_cond = 0;
static DisassemblerParams * params;

static const char * shift_names[] = { "lsl", "lsr", "asr", "ror" };

static const char * cond_names[] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "", "nv"
};

static const char * reg_names[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
};

static void add_char(char ch) {
    if (buf_pos >= sizeof(buf) - 1) return;
    buf[buf_pos++] = ch;
    if (ch == ' ') while (buf_pos < 8) buf[buf_pos++] = ch;
}

static void add_str(const char * s) {
    while (*s) add_char(*s++);
}

static void add_dec_uint32(uint32_t n) {
    char s[32];
    size_t i = 0;
    do {
        s[i++] = '0' + n % 10;
        n = n / 10;
    }
    while (n != 0);
    while (i > 0) add_char(s[--i]);
}

static void add_hex_uint32(uint32_t n) {
    char s[32];
    size_t i = 0;
    while (i < 8) {
        uint32_t d = n & 0xf;
        s[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        n = n >> 4;
    }
    while (i > 0) add_char(s[--i]);
}

#define add_reg_name(reg) add_str(reg_names[(reg) & 0xf])

static void add_modifed_immediate_constant(uint16_t suffix) {
    uint32_t rot = (suffix >> 12) & 7;
    uint32_t val = suffix & 0xff;
    uint32_t dec = 0;
    if (instr & (1 << 10)) rot |= 8;
    switch (rot) {
    case 0:
        break;
    case 1:
        val |= val << 16;
        break;
    case 2:
        val = (val << 8) | (val << 24);
        break;
    case 3:
        val |= (val << 8) | (val << 16) | (val << 24);
        break;
    default:
        rot = rot << 1;
        if (val & 0x80) rot |= 1;
        val |= 0x80;
        val = (val >> rot) | (val << (32 - rot));
        break;
    }
    add_char('#');
    dec = val;
#if 0
    if (dec & 0x80000000) {
        add_char('-');
        dec = ~dec + 1;
    }
#endif
    add_dec_uint32(dec);
#if 0
    if (val > 0x10) {
        add_str(" ; 0x");
        add_hex_uint32(val);
    }
#endif
}

static void add_branch_address(int32_t offset) {
    add_char(' ');
    if (offset < 0) {
        add_char('-');
        add_dec_uint32(-offset);
    }
    else {
        add_char('+');
        add_dec_uint32(offset);
    }
    add_str(" ; addr=0x");
    add_hex_uint32(instr_addr + offset + 4);
}

static void disassemble_thumb0(void) {
    uint32_t op;
    uint32_t imm;

    if ((instr & 0xf800) == 0x1800) {
        /* Add/substruct register/immediate */
        add_str(instr & (1 << 9) ? "sub" : "add");
        add_str(it_cond_name ? it_cond_name : "s");
        add_char(' ');
        add_reg_name(instr & 7);
        add_str(", ");
        add_reg_name((instr >> 3) & 7);
        add_str(", ");
        if (instr & (1 << 10)) {
            add_char('#');
            add_dec_uint32((instr >> 6) & 7);
        }
        else {
            add_reg_name((instr >> 6) & 7);
        }
        return;
    }

    /* Shift by immediate */
    op = (instr >> 11) & 3;
    imm = (instr >> 6) & 0x1f;
    switch (op) {
    case 0: add_str(imm ? "lsl" : "mov"); break;
    case 1: add_str("lsr"); break;
    case 2: add_str("asr"); break;
    }
    add_str(it_cond_name ? it_cond_name : "s");
    add_char(' ');
    add_reg_name(instr & 7);
    add_str(", ");
    add_reg_name((instr >> 3) & 7);
    if (imm || op) {
        add_str(", #");
        add_dec_uint32(imm);
    }
}

static void disassemble_thumb1(void) {
    /* Add/substruct/compare/move immediate */
    uint32_t op = (instr >> 11) & 3;
    switch(op) {
    case 0: add_str("mov"); break;
    case 1: add_str("cmp"); break;
    case 2: add_str("add"); break;
    case 3: add_str("sub"); break;
    }
    if (it_cond_name) add_str(it_cond_name);
    else if (op != 1) add_char('s');
    add_char(' ');
    add_reg_name((instr >> 8) & 7);
    add_str(", #");
    add_dec_uint32(instr & 0xff);
}

static void disassemble_thumb2(void) {
    if ((instr & 0xfc00) == 0x4000) {
        /* Data-processing register */
        uint32_t op = (instr >> 6) & 0xf;
        switch (op) {
        case  0: add_str("and"); break;
        case  1: add_str("eor"); break;
        case  2: add_str("lsl"); break;
        case  3: add_str("lsr"); break;
        case  4: add_str("asr"); break;
        case  5: add_str("adc"); break;
        case  6: add_str("sbc"); break;
        case  7: add_str("ror"); break;
        case  8: add_str("tst"); break;
        case  9: add_str("rsb"); break;
        case 10: add_str("cmp"); break;
        case 11: add_str("cmn"); break;
        case 12: add_str("orr"); break;
        case 13: add_str("mul"); break;
        case 14: add_str("bic"); break;
        case 15: add_str("mvn"); break;
        }
        if (it_cond_name) add_str(it_cond_name);
        else if (op != 8 && op != 10 && op != 11) add_char('s');
        add_char(' ');
        add_reg_name(instr & 7);
        add_str(", ");
        add_reg_name((instr >> 3) & 7);
        return;
    }

    if ((instr & 0xff00) == 0x4700) {
        /* Branch/exchange */
        add_char('b');
        if (instr & (1 << 7)) add_char('l');
        add_char('x');
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name((instr >> 3) & 0xf);
        return;
    }

    if ((instr & 0xfc00) == 0x4400) {
        /* Special data processing */
        unsigned rd = instr & 7;
        if (instr & (1 << 7)) rd += 8;
        switch ((instr >> 8) & 3) {
        case 0: add_str("add"); break;
        case 1: add_str("cmp"); break;
        case 2: add_str("mov"); break;
        }
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name(rd);
        add_str(", ");
        add_reg_name((instr >> 3) & 0xf);
        return;
    }

    if ((instr & 0xf800) == 0x4800) {
        /* Load from literal pool */
        add_str("ldr");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name((instr >> 8) & 7);
        add_str(", [pc, #");
        add_dec_uint32((instr & 0xff) << 2);
        add_char(']');
        return;
    }

    /* Load/store register offset */
    switch ((instr >> 9) & 7) {
    case 0: add_str("str"); break;
    case 1: add_str("strh"); break;
    case 2: add_str("strb"); break;
    case 3: add_str("ldrsb"); break;
    case 4: add_str("ldr"); break;
    case 5: add_str("ldrh"); break;
    case 6: add_str("ldrb"); break;
    case 7: add_str("ldrsh"); break;
    }
    if (it_cond_name) add_str(it_cond_name);
    add_char(' ');
    add_reg_name(instr & 7);
    add_str(", [");
    add_reg_name((instr >> 3) & 7);
    add_str(", ");
    add_reg_name((instr >> 6) & 7);
    add_char(']');
}

static void disassemble_thumb3(void) {
    /* Load/store word/byte immediate offset */
    uint32_t imm = (instr >> 6) & 0x1f;
    int B = (instr & (1 << 12)) != 0;
    if (!B) imm = imm << 2;
    add_str(instr & (1 << 11) ? "ldr" : "str");
    if (B) add_char('b');
    if (it_cond_name) add_str(it_cond_name);
    add_char(' ');
    add_reg_name(instr & 7);
    add_str(", [");
    add_reg_name((instr >> 3) & 7);
    add_str(", #");
    add_dec_uint32(imm);
    add_char(']');
}

static void disassemble_thumb4(void) {
    add_str(instr & (1 << 11) ? "ldr" : "str");

    if ((instr & 0xf000) == 0x8000) {
        /* Load/store halfword immediate offset */
        add_char('h');
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name(instr & 7);
        add_str(", [");
        add_reg_name((instr >> 3) & 7);
        add_str(", #");
        add_dec_uint32(((instr >> 6) & 0x1f) << 1);
        add_char(']');
        return;
    }

    /* Load/store to/from stack */
    if (it_cond_name) add_str(it_cond_name);
    add_char(' ');
    add_reg_name((instr >> 8) & 7);
    add_str(", [sp, #");
    add_dec_uint32((instr & 0xff) << 2);
    add_char(']');
}

static void disassemble_thumb5(void) {
    if ((instr & 0xf000) == 0xa000) {
        /* Add to SP or PC */
        add_str("add");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name((instr >> 8) & 7);
        add_str(", ");
        add_str(instr & (1 << 11) ? "sp" : "pc");
        add_str(", #");
        add_dec_uint32((instr & 0xff) << 2);
        return;
    }

    if ((instr & 0xff00) == 0xb000) {
        /* Adjust stack pointer */
        add_str(instr & (1 << 7) ? "sub" : "add");
        if (it_cond_name) add_str(it_cond_name);
        add_str(" sp, #");
        add_dec_uint32((instr & 0x7f) << 2);
        return;
    }

    if ((instr & 0xf600) == 0xb400) {
        /* Push/pop register list */
        int cnt = 0;
        unsigned reg;
        add_str(instr & (1 << 11) ? "pop" : "push");
        if (it_cond_name) add_str(it_cond_name);
        add_str(" {");
        for (reg = 0; reg < 8; reg++) {
            if ((instr & (1 << reg)) == 0) continue;
            if (cnt > 0) add_str(", ");
            add_reg_name(reg);
            cnt++;
        }
        if (instr & (1 << 8)) {
            if (cnt > 0) add_str(", ");
            add_str(instr & (1 << 11) ? "pc" : "lr");
        }
        add_char('}');
        return;
    }

    if ((instr & 0xff00) == 0xbe00) {
        /* Software breakpoint */
        add_str("bkpt");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_dec_uint32(instr & 0xff);
        return;
    }

    if ((instr & 0xffe0) == 0xb640) {
        add_str("setend");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_str(instr & (1 << 3) ? "be" : "le");
        return;
    }

    if ((instr & 0xffe0) == 0xb660) {
        add_str("cps");
        add_str(instr & (1 << 4) ? "id" : "ie");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        if (instr & (1 << 0)) add_char('f');
        if (instr & (1 << 1)) add_char('i');
        if (instr & (1 << 2)) add_char('a');
        return;
    }

    if ((instr & 0xf500) == 0xb100) {
        uint32_t offs = (instr >> 3) & 0x1f;
        if (instr & (1 << 9)) offs |= 0x20;
        add_str("cb");
        if (instr & (1 << 11)) add_char('n');
        add_char('z');
        add_char(' ');
        add_reg_name(instr & 7);
        add_str(", ");
        add_hex_uint32(instr_addr + 4 + (offs << 1));
        return;
    }

    if ((instr & 0xff00) == 0xb200) {
        add_char(instr & (1 << 7) ? 'u' : 's');
        add_str("xt");
        add_char(instr & (1 << 6) ? 'b' : 'h');
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name(instr & 7);
        add_str(", ");
        add_reg_name((instr >> 3) & 7);
        return;
    }

    if ((instr & 0xff00) == 0xba00) {
        add_str("rev");
        switch ((instr >> 6) & 3) {
        case 1: add_str("16"); break;
        case 3: add_str("sh"); break;
        }
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name(instr & 7);
        add_str(", ");
        add_reg_name((instr >> 3) & 7);
        return;
    }

    if ((instr & 0xff00) == 0xbf00) {
        if (instr & 0x000f) {
            /* If-Then */
            it_mask = instr & 0xf;
            it_cond = (instr >> 4) & 0xf;
            add_str("it");
            it_pos = 0;
            it_cnt = 1;
            if (it_mask & 7) {
                char a = it_cond & 1 ? 't' : 'e';
                char b = it_cond & 1 ? 'e' : 't';
                add_char(it_mask & 0x8 ? a : b);
                it_cnt++;
                if (it_mask & 3) {
                    add_char(it_mask & 0x4 ? a : b);
                    it_cnt++;
                    if (it_mask & 1) {
                        add_char(it_mask & 0x2 ? a : b);
                        it_cnt++;
                    }
                }
            }
            add_char(' ');
            add_str(cond_names[it_cond]);
            return;
        }
        switch ((instr >> 4) & 0xf) {
        case 0: add_str("nop"); break;
        case 1: add_str("yield"); break;
        case 2: add_str("wfe"); break;
        case 3: add_str("wfi"); break;
        case 4: add_str("sev"); break;
        }
        if (buf_pos > 0) {
            if (it_cond_name) add_str(it_cond_name);
            return;
        }
    }
}

static void disassemble_thumb6(void) {
    if ((instr & 0xff00) == 0xdf00) {
        /* Software interrupt */
        add_str("swi");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_dec_uint32(instr & 0xff);
        return;
    }

    if ((instr & 0xff00) == 0xde00) {
        /* Undefined instruction */
        return;
    }

    if ((instr & 0xf000) == 0xd000) {
        /* Conditional branch */
        int32_t offset = instr & 0x00ff;
        if (offset & 0x0080) offset |= ~0x00ff;
        offset = offset << 1;
        add_char('b');
        add_str(cond_names[(instr >> 8) & 0xf]);
        add_str(".n");
        add_branch_address(offset);
        return;
    }

    {
        /* Load/store multiple */
        int cnt = 0;
        uint32_t rn = (instr >> 8) & 7;
        uint32_t regs = instr & 0xff;
        unsigned reg;
        add_str(instr & (1 << 11) ? "ldmia" : "stmia");
        if (it_cond_name) add_str(it_cond_name);
        add_char(' ');
        add_reg_name(rn);
        if ((regs & (1 << rn)) == 0) add_char('!');
        add_str(", {");
        for (reg = 0; reg < 8; reg++) {
            if ((regs & (1 << reg)) == 0) continue;
            if (cnt > 0) add_str(", ");
            add_reg_name(reg);
            cnt++;
        }
        add_char('}');
    }
}

static void disassemble_load_store_32(uint16_t suffix) {
    if ((instr & (1 << 6)) == 0) {
        /* Load/store multiple */
        unsigned i, j;
        uint32_t op = (instr >> 7) & 3;
        int L = (instr & (1 << 4)) != 0;
        int W = (instr & (1 << 5)) != 0;
        if (op == 0 || op == 3) {
            if (!L) {
                add_str("srs");
                if (op == 0) add_str("db");
                if (it_cond_name) add_str(it_cond_name);
                add_char(' ');
                add_str("sp");
                if (W) add_char('!');
                add_str(", #");
                add_dec_uint32(suffix & 0x1f);
            }
            else {
                add_str("rfe");
                if (op == 0) add_str("db");
                if (it_cond_name) add_str(it_cond_name);
                add_char(' ');
                add_reg_name(instr & 0xf);
                if (W) add_char('!');
            }
            return;
        }
        if (instr == 0xe92d) {
            add_str("push");
            if (it_cond_name) add_str(it_cond_name);
            add_str(".w");
        }
        else if (instr == 0xe8bd) {
            add_str("pop");
            if (it_cond_name) add_str(it_cond_name);
            add_str(".w");
        }
        else {
            add_str(L ? "ldm" : "stm");
            add_str(instr & (1 << 8) ? "db" : "ia");
            if (it_cond_name) add_str(it_cond_name);
            add_str(".w");
            add_char(' ');
            add_reg_name(instr & 0xf);
            if (W) add_char('!');
            add_char(',');
        }
        add_str(" {");
        for (i = 0, j = 0; i < 16; i++) {
            if (suffix & (1 << i)) {
                if (j) add_char(',');
                add_reg_name(i);
                j++;
            }
        }
        add_char('}');
        return;
    }

    if ((instr & 0xfff0) == 0xe8d0 && (suffix & 0x00e0) == 0x0000) {
        /* Table Branch */
        add_str("tb");
        add_char(suffix & (1 << 4) ? 'h' : 'b');
        if (it_cond_name) add_str(it_cond_name);
        add_str(" [");
        add_reg_name(instr & 0xf);
        add_str(", ");
        add_reg_name(suffix & 0xf);
        add_char(']');
        return;
    }
}

static void disassemble_data_processing_32(uint16_t suffix) {
    uint32_t op_code = (instr >> 5) & 0xf;
    int I = (instr & (1 << 9)) == 0;
    int S = (instr & (1 << 4)) != 0;
    uint32_t rn = instr & 0xf;
    uint32_t rd = (suffix >> 8) & 0xf;
    int no_rd = 0;
    int no_rn = 0;

    switch (op_code) {
    case 0:
        if (rd == 15) {
            if (!S) return;
            S = 0;
            no_rd = 1;
        }
        add_str(rd == 15 ? "tst" : "and");
        break;
    case 1:
        add_str("bic");
        break;
    case 2:
        add_str(rn == 15 ? "mov" : "orr");
        no_rn = rn == 15;
        break;
    case 3:
        add_str(rn == 15 ? "mvn" : "orn");
        no_rn = rn == 15;
        break;
    case 4:
        if (rd == 15) {
            if (!S) return;
            S = 0;
            no_rd = 1;
        }
        add_str(rd == 15 ? "teq" : "eor");
        break;
    case 6:
        add_str("pkh");
        break;
    case 8:
        if (rd == 15) {
            if (!S) return;
            S = 0;
            no_rd = 1;
        }
        add_str(rd == 15 ? "cmn" : "add");
        break;
    case 10:
        add_str("adc");
        break;
    case 11:
        add_str("sbc");
        break;
    case 13:
        if (rd == 15) {
            if (!S) return;
            S = 0;
            no_rd = 1;
        }
        add_str(rd == 15 ? "cmp" : "sub");
        break;
    case 14:
        add_str("rsb");
        break;
    default:
        return;
    }

    if (it_cond_name) add_str(it_cond_name);
    else if (S) add_char('s');
    if (op_code != 14 && (op_code != 4 || rd != 15)) add_str(".w");
    add_char(' ');

    if (!no_rd) {
        add_reg_name(rd);
        add_str(", ");
    }

    if (!no_rn) {
        add_reg_name(rn);
        add_str(", ");
    }

    if (!I) {
        uint8_t rm = (suffix & 0xf);
        uint32_t shift_imm = ((suffix >> 10) & 0x1c) | ((suffix >> 6) & 3);
        uint32_t shift_type = (suffix >> 4) & 3;

        add_reg_name(rm);
        if (shift_type != 0 || shift_imm != 0) {
            if (shift_type == 3 && shift_imm == 0) {
                add_str(", ");
                add_str("rrx");
            }
            else {
                add_str(", ");
                add_str(shift_names[shift_type]);
                add_char(' ');
                add_char('#');
                if (shift_type >= 1 && shift_imm == 0) shift_imm = 32;
                add_dec_uint32(shift_imm);
            }
        }
    }
    else {
        add_modifed_immediate_constant(suffix);
    }
}

static void disassemble_data_processing_pbi_32(uint16_t suffix) {
    uint32_t op_code = (instr >> 4) & 0x1f;
    uint32_t rn = instr & 0xf;
    uint32_t imm = suffix & 0xff;

    imm |= (suffix & 0x7000) >> 4;
    if (instr & (1 << 10)) imm |= 0x800;

    switch (op_code) {
    case 0:
        add_str("addw");
        break;
    case 4:
        add_str("movw");
        break;
    case 10:
        add_str("subw");
        break;
    case 12:
        add_str("movt");
        break;
    case 16:
        add_str("ssat");
        break;
    case 18:
        add_str(suffix & 0x70c0 ? "ssat" : "ssat16");
        break;
    case 20:
        add_str("sbfx");
        break;
    case 22:
        add_str(rn == 15 ? "bfc" : "bfi");
        break;
    case 24:
        add_str("usat");
        break;
    case 26:
        add_str(suffix & 0x70c0 ? "usat" : "usat16");
        break;
    case 28:
        add_str("ubfx");
        break;
    default:
        buf_pos = 0;
        return;
    }

    if (it_cond_name) add_str(it_cond_name);
    add_char(' ');
    add_reg_name((suffix >> 8) & 0xf);
    if (op_code != 4) {
        add_str(", ");
        add_reg_name(rn);
    }
    add_str(", #");
    add_dec_uint32(imm);
}

static void disassemble_thumb7(void) {
    unsigned i;
    uint16_t suffix = 0;

    if ((instr & 0xf800) == 0xe000) {
        /* Unconditional branch */
        int32_t offset = instr & 0x07ff;
        if (offset & 0x0400) offset |= ~0x07ff;
        offset = offset << 1;
        add_char('b');
        if (it_cond_name) add_str(it_cond_name);
        add_str(".n");
        add_branch_address(offset);
        return;
    }

    instr_size = 4;
    for (i = 0; i < 2; i++) suffix |= (uint16_t)*instr_code++ << (i * 8);

    if ((instr & 0xfe00) == 0xe800) {
        disassemble_load_store_32(suffix);
        return;
    }

    if ((instr & 0xfe00) == 0xea00) {
        disassemble_data_processing_32(suffix);
        return;
    }

    if ((instr & 0xf800) == 0xf000) {

        if ((suffix & 0x8000) == 0) {
            if (instr & (1 << 9)) {
                disassemble_data_processing_pbi_32(suffix);
            }
            else {
                disassemble_data_processing_32(suffix);
            }
            return;
        }

        if ((suffix & 0xd000) == 0x8000) {
            uint16_t op = (instr >> 4) & 0x7f;
            if ((op & 0x38) != 0x38) {
                /* Conditional branch */
                int J1 = (suffix & (1 << 13)) != 0;
                int J2 = (suffix & (1 << 11)) != 0;
                int S = (instr & (1 << 10)) != 0;
                int32_t offset = suffix & 0x7ff;
                offset |= (instr & 0x3f) << 11;
                if (J2) offset |= 1 << 17;
                if (J1) offset |= 1 << 18;
                if (S) offset |= 0xfff80000;
                offset = offset << 1;
                add_char('b');
                add_str(cond_names[(instr >> 6) & 0xf]);
                add_str(".w");
                add_branch_address(offset);
                return;
            }
            if ((op & 0x7e) == 0x38) {
                /* Move to Special Register */
                int R = 0;
                uint32_t mask = (suffix >> 8) & 0xf;
                if ((suffix & 0x0300) != 0x0000) {
                    R = (instr & (1 << 4)) != 0;
                }
                if (mask) {
                    add_str("msr");
                    if (it_cond_name) add_str(it_cond_name);
                    add_char(' ');
                    add_str(R ? "spsr" : "cpsr");
                    add_char('_');
                    if (mask & 8) add_char('f');
                    if (mask & 4) add_char('s');
                    if (mask & 2) add_char('x');
                    if (mask & 1) add_char('c');
                    add_str(", ");
                    add_reg_name(instr & 0xf);
                    return;
                }
                return;
            }
            if (op == 0x3a) {
                /* Change Processor State, and hints */
                uint32_t imod = (suffix >> 9) & 3;
                int M = (suffix & (1 << 8)) != 0;
                if (imod || M) {
                    uint32_t mode = instr & 0x1f;
                    add_str("cps");
                    if (imod >= 2) {
                        add_str(imod == 2 ? "ie" : "id");
                        add_str(".w");
                        add_char(' ');
                        if (instr & (1 << 7)) add_char('a');
                        if (instr & (1 << 6)) add_char('i');
                        if (instr & (1 << 5)) add_char('f');
                        if (M) {
                            add_str(", #");
                            add_dec_uint32(mode);
                        }
                    }
                    else {
                        add_str(".w #");
                        add_dec_uint32(mode);
                    }
                    return;
                }
                switch (suffix & 0xff) {
                case 0: add_str("nop"); break;
                case 1: add_str("yield"); break;
                case 2: add_str("wfe"); break;
                case 3: add_str("wfi"); break;
                case 4: add_str("sev"); break;
                }
                if (buf_pos > 0) {
                    if (it_cond_name) add_str(it_cond_name);
                    return;
                }
                if ((suffix & 0x00f0) == 0x00f0) {
                    add_str("bdg");
                    if (it_cond_name) add_str(it_cond_name);
                    add_str(" #");
                    add_dec_uint32(suffix & 0xf);
                    return;
                }
                return;
            }
            if (op == 0x3b) {
                /* Miscellaneous control instructions */
                uint32_t op = (suffix >> 4) & 0xf;
                switch (op) {
                case 0: add_str("leavex"); break;
                case 1: add_str("enterx"); break;
                case 2: add_str("clrex"); break;
                case 4: add_str("dsb"); break;
                case 5: add_str("dmb"); break;
                case 6: add_str("isb"); break;
                }
                if (op >= 4 && op <= 6) {
                    if (it_cond_name) add_str(it_cond_name);
                    add_char(' ');
                    switch (suffix & 0xf) {
                    case 15: add_str("sy"); break;
                    case 14: add_str("st"); break;
                    case 11: add_str("ish"); break;
                    case 10: add_str("ishst"); break;
                    case 7: add_str("nsh"); break;
                    case 6: add_str("nshst"); break;
                    case 3: add_str("osh"); break;
                    case 2: add_str("oshst"); break;
                    default:
                        add_str(" #");
                        add_dec_uint32(suffix & 0xf);
                    }
                    return;
                }
                return;
            }
            if (op == 0x3c) {
                /* Branch and Exchange Jazelle */
                return;
            }
            if (op == 0x3d) {
                /* Exception Return */
                return;
            }
            if ((op & 0x7e) == 0x3e) {
                /* Move from Special Register */
                add_str("mrs");
                if (it_cond_name) add_str(it_cond_name);
                add_char(' ');
                add_reg_name((suffix >> 8) & 0xf);
                add_str(", cpsr");
                return;
            }
            if (op == 0x7f) {
                if (suffix & 0x2000) {
                    /* Permanently UNDEFINED.
                     * This space will not be allocated in future */
                    return;
                }
                /* Secure Monitor Call */
                return;
            }
            /* Undefined */
            return;
        }

        {
            /* B/BL/BLX */
            int w = 0;
            int J1 = (suffix & (1 << 13)) != 0;
            int J2 = (suffix & (1 << 11)) != 0;
            int S = (instr & (1 << 10)) != 0;
            int32_t offset = suffix & 0x7ff;
            offset |= (instr & 0x3ff) << 11;
            if (S == J2) offset |= 1 << 21;
            if (S == J1) offset |= 1 << 22;
            if (S) offset |= 0xff800000;
            offset = offset << 1;
            if ((suffix & 0xd000) == 0x9000) {
                add_str("b");
                w = 1;
            }
            else if ((suffix & 0xf800) == 0xe800) {
                add_str("blx");
            }
            else {
                add_str("bl");
            }
            if (it_cond_name) add_str(it_cond_name);
            if (w) add_str(".w");
            add_branch_address(offset);
            return;
        }
    }

    if ((instr & 0xfe00) == 0xf800) {
        if ((instr & (1 << 4)) && (suffix & 0xf000) == 0xf000) {
            /* Memory hints */
            return;
        }

        /* Load/Store single data item */
        add_str(instr & (1 << 4) ? "ldr" : "str");
        if ((instr &  (1 << 6)) == 0) {
            if (instr & (1 << 8)) add_char('s');
            add_char(instr & (1 << 5) ? 'h' : 'b');
        }
        if ((suffix & 0x0f00) == 0x0e00) add_char('t');
        if (it_cond_name) add_str(it_cond_name);
        add_str(".w");
        add_char(' ');
        add_reg_name((suffix >> 12) & 0xf);
        add_str(", [");
        add_reg_name(instr & 0xf);
        if (instr & (1 << 7)) {
            uint32_t imm = suffix & 0xfff;
            if (imm) {
                add_str(", #");
                add_dec_uint32(imm);
            }
            add_char(']');
        }
        else if ((suffix & (1 << 11)) == 0) {
            uint32_t imm = (suffix >> 4) & 3;
            add_str(", ");
            add_reg_name(suffix & 0xf);
            if (imm) {
                add_str(", lsl #");
                add_dec_uint32(imm);
            }
            add_char(']');
        }
        else if ((suffix & (1 << 8)) == 0) {
            uint32_t imm = suffix & 0xff;
            if (imm) {
                add_str(", #");
                add_char(suffix & (1 << 9) ? '+' : '-');
                add_dec_uint32(imm);
            }
            add_char(']');
        }
        else if (suffix & (1 << 10)) {
            uint32_t imm = suffix & 0xff;
            if (imm) {
                add_str(", #");
                add_char(suffix & (1 << 9) ? '+' : '-');
                add_dec_uint32(imm);
            }
            add_str("]!");
        }
        else {
            uint32_t imm = suffix & 0xff;
            add_str("], #");
            add_char(suffix & (1 << 9) ? '+' : '-');
            add_dec_uint32(imm);
        }
        return;
    }

    if ((instr & 0xfe00) == 0xfc00) {
        if ((instr & (1 << 8)) == 0) {
            /* Data-processing (register) */
        }
        else if ((instr & (1 << 7)) == 0) {
            /* Multiply, multiply accumulate, and absolute difference */
        }
        else {
            /* Long multiply, long multiply accumulate, and divide */
        }
    }
}

static DisassemblyResult * disassemble_arm_ti(uint8_t * code, ContextAddress addr, ContextAddress size) {
    const char * p;
    DisassemblyResult * dr = disassemble_arm(code, addr, size, params);
    if (dr == NULL || dr->text == NULL || it_cond_name == NULL) return dr;
    p = dr->text;
    while (*p && *p != ' ') buf[buf_pos++] = *p++;
    add_str(it_cond_name);
    while (*p == ' ') p++;
    buf[buf_pos++] = ' ';
    while (buf_pos < 8) buf[buf_pos++] = ' ';
    while (*p) buf[buf_pos++] = *p++;
    buf[buf_pos] = 0;
    dr->text = buf;
    return dr;
}

DisassemblyResult * disassemble_thumb(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * prm) {
    unsigned i;
    static DisassemblyResult dr;

    if (size < 2) return NULL;

    instr = 0;
    for (i = 0; i < 2; i++) instr |= (uint16_t)code[i] << (i * 8);
    memset(&dr, 0, sizeof(dr));
    params = prm;

    instr_size = 2;
    instr_addr = (uint32_t)addr;
    instr_code = code + 2;
    buf_pos = 0;

    it_cond_name = NULL;
    if (it_cnt > 0) {
        if (it_pos == 0) {
            it_cond_name = cond_names[it_cond];
        }
        else if (it_mask & (1 << (4 - it_pos))) {
            it_cond_name = cond_names[it_cond | 1u];
        }
        else {
            it_cond_name = cond_names[it_cond & ~1u];
        }
        it_pos++;
        it_cnt--;
    }

    if ((instr & 0xec00) == 0xec00 && size >= 4) {
        /* Coprocessor instructions - same as ARM encoding */
        uint8_t tmp[4];
        tmp[2] = code[0];
        tmp[3] = code[1];
        tmp[0] = code[2];
        tmp[1] = code[3];
        return disassemble_arm_ti(tmp, addr, 4);
    }

    if ((instr & 0xff10) == 0xf900 && size >= 4) {
        /* Advanced SIMD element or structure load/store instructions */
        uint8_t tmp[4];
        tmp[2] = code[0];
        tmp[3] = 0xf4;
        tmp[0] = code[2];
        tmp[1] = code[3];
        return disassemble_arm_ti(tmp, addr, 4);
    }

    switch ((instr >> 13) & 7) {
    case 0: disassemble_thumb0(); break;
    case 1: disassemble_thumb1(); break;
    case 2: disassemble_thumb2(); break;
    case 3: disassemble_thumb3(); break;
    case 4: disassemble_thumb4(); break;
    case 5: disassemble_thumb5(); break;
    case 6: disassemble_thumb6(); break;
    case 7: disassemble_thumb7(); break;
    }

    dr.text = buf;
    dr.size = instr_size;
    dr.incomplete = it_cnt > 0;
    if (buf_pos == 0) {
        if (dr.size == 2) snprintf(buf, sizeof(buf), ".half 0x%04x", instr);
        else dr.text = NULL;
    }
    else {
        buf[buf_pos] = 0;
    }
    return &dr;
}
