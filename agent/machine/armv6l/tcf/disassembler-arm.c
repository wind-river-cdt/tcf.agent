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

#include <assert.h>
#include <stdio.h>
#include <tcf/framework/context.h>
#include <machine/arm/tcf/disassembler-arm.h>

static char buf[128];
static size_t buf_pos = 0;

static const char * shift_names[] = { "lsl", "lsr", "asr", "ror" };

static const char * op_names[] = {
    "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
    "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"
};

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
        s[i++] = (char)('0' + n % 10);
        n = n / 10;
    }
    while (n != 0);
    while (i > 0) add_char(s[--i]);
}

static void add_dec_uint64(uint64_t n) {
    char s[64];
    size_t i = 0;
    do {
        s[i++] = (char)('0' + (int)(n % 10));
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

static void add_hex_uint64(uint64_t n) {
    char s[64];
    size_t i = 0;
    while (i < 16) {
        uint32_t d = n & 0xf;
        s[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        n = n >> 4;
    }
    while (i > 0) add_char(s[--i]);
}

static void add_flt_uint32(uint32_t n) {
    char buf[32];
    union {
        uint32_t n;
        float f;
    } u;
    u.n = n;
    snprintf(buf, sizeof(buf), "%g", u.f);
    add_str(buf);
}

static void add_flt_uint64(uint64_t n) {
    char buf[32];
    union {
        uint64_t n;
        double d;
    } u;
    u.n = n;
    snprintf(buf, sizeof(buf), "%g", u.d);
    add_str(buf);
}

#define add_reg_name(reg) add_str(reg_names[(reg) & 0xf])

static void add_modifed_immediate_constant(uint32_t n) {
    uint32_t rot = ((n >> 8) & 0xf) * 2;
    uint32_t val = n & 0xff;
    val = (val >> rot) | (val << (32 - rot));
    add_char('#');
    if (val & 0x80000000) {
        add_char('-');
        val = ~val + 1;
    }
    add_dec_uint32(val);
}

static void add_shift(uint32_t instr, int no_shift_name) {
    uint8_t rm = (instr & 0x000f);
    uint32_t shift_imm = (instr >> 7) & 0x1f;
    uint32_t shift_type = (instr >> 5) & 3;
    int reg_shift = (instr & 0x00000010) != 0;

    add_reg_name(rm);
    if (reg_shift || shift_type != 0 || shift_imm != 0) {
        if (reg_shift) {
            add_str(", ");
            if (!no_shift_name) {
                add_str(shift_names[shift_type]);
                add_char(' ');
            }
            add_reg_name((instr & 0x0f00) >> 8);
        }
        else if (shift_type == 3 && shift_imm == 0) {
            if (!no_shift_name) {
                add_str(", ");
                add_str("rrx");
            }
        }
        else {
            add_str(", ");
            if (!no_shift_name) {
                add_str(shift_names[shift_type]);
                add_char(' ');
            }
            add_char('#');
            if (shift_type >= 1 && shift_imm == 0) shift_imm = 32;
            add_dec_uint32(shift_imm);
        }
    }
}

static void add_addressing_mode(uint32_t instr) {
    int I = (instr & (1 << 25)) != 0;
    int P = (instr & (1 << 24)) != 0;
    int U = (instr & (1 << 23)) != 0;
    int W = (instr & (1 << 21)) != 0;
    uint32_t rn = (instr & 0x000f0000) >> 16;

    add_char('[');
    add_reg_name(rn);

    if (!I && P) {
        uint32_t offs = instr & 0xfff;
        if (offs != 0 || W) {
            add_str(", #");
            add_char(U ? '+' : '-');
            add_dec_uint32(offs);
        }
        add_char(']');
        if (W) add_char('!');
    }
    else if (I && P) {
        add_str(", ");
        add_char(U ? '+' : '-');
        add_shift(instr, 0);
        add_char(']');
        if (W) add_char('!');
    }
    else if (!I && !P && !W) {
        add_str("], #");
        add_char(U ? '+' : '-');
        add_dec_uint32(instr & 0xfff);
    }
    else if (I && !P && !W) {
        add_str("], ");
        add_char(U ? '+' : '-');
        add_shift(instr, 0);
    }
    else {
        add_str(" ?]");
    }
}

static void add_auto_inc_mode(uint32_t instr, int no_ia) {
    switch ((instr >> 23) & 3) {
    case 0: add_str("da"); break;
    case 1: if (!no_ia) add_str("ia"); break;
    case 2: add_str("db"); break;
    case 3: add_str("ib"); break;
    }
}

static uint32_t vfp_expand_imm32(uint32_t n) {
    uint32_t v = 0;
    if (n & (1 << 7)) v |= 1 << 31;
    if (n & (1 << 6)) v |= 0x1f << 25;
    else v |= 1 << 30;
    v |= (n & 0x3f) << 19;
    return v;
}

static uint64_t vfp_expand_imm64(uint32_t n) {
    uint64_t v = 0;
    if (n & (1 << 7)) v |= (uint64_t)1 << 63;
    if (n & (1 << 6)) v |= (uint64_t)0xff << 54;
    else v |= (uint64_t)1 << 62;
    v |= (uint64_t)(n & 0x3f) << 48;
    return v;
}

static uint64_t adv_simd_expand_imm(uint32_t instr) {
    unsigned i;
    uint64_t imm64 = 0;
    int op = (instr & (1 << 5)) != 0;
    uint32_t cmode = (instr >> 8) & 0xf;
    uint32_t imm8 = instr & 0xf;
    imm8 |= (instr >> 12) & 0x70;
    if (instr & (1 << 24)) imm8 |= 0x80;
    switch (cmode / 2) {
    case 0:
        return (imm8 << 0) | ((uint64_t)imm8 << 32);
    case 1:
        return (imm8 << 8) | ((uint64_t)imm8 << 40);
    case 2:
        return (imm8 << 16) | ((uint64_t)imm8 << 48);
    case 3:
        return (imm8 << 24) | ((uint64_t)imm8 << 56);
    case 4:
        return (imm8 << 0) | ((uint64_t)imm8 << 32) |
               (imm8 << 16) | ((uint64_t)imm8 << 48);
    case 5:
        return (imm8 << 8) | ((uint64_t)imm8 << 40) |
               (imm8 << 24) | ((uint64_t)imm8 << 56);
    case 6:
        if ((cmode & 1) == 0) {
            imm64 = (imm8 << 8) | 0xff;
        }
        else {
            imm64 = (imm8 << 16) | 0xffff;
        }
        return imm64 | (imm64 << 32);
    case 7:
        if ((cmode & 1) == 0 && op == 0) {
            for (i = 0; i < 8; i++) imm64 |= (uint64_t)imm8 << i * 8;
            return imm64;
        }
        if ((cmode & 1) == 0 && op == 1) {
            for (i = 0; i < 8; i++) {
                if (imm8 & (1 << i)) imm64 |= 0xff << i * 8;
            }
            return imm64;
        }
        if ((cmode & 1) == 1 && op == 0) {
            if (imm8 & (1 << 7)) imm64 |= 1 << 31;
            if (imm8 & (1 << 6)) imm64 |= 0x1f << 25;
            else imm64 |= 1 << 30;
            imm64 |= (imm8 & 0x3f) << 19;
            return imm64 | (imm64 << 32);
        }
        break;
    }
    return imm64;
}

static void disassemble_advanced_simd_data_processing(uint32_t instr) {
    if ((instr & 0xfe800000) == 0xf2000000) {
        uint32_t sz = (instr >> 20) & 3;
        int U = (instr & (1 << 24)) != 0;
        int D = (instr & (1 << 22)) != 0;
        int N = (instr & (1 << 7)) != 0;
        int Q = (instr & (1 << 6)) != 0;
        int M = (instr & (1 << 5)) != 0;
        uint32_t vd = (instr >> 12) & 0xf;
        uint32_t vn = (instr >> 16) & 0xf;
        uint32_t vm = instr & 0xf;
        int no_dt = 0;
        char fmt = 0;
        if (D) vd |= 0x10;
        if (N) vn |= 0x10;
        if (M) vm |= 0x10;
        if (instr & (1 << 23)) {
        }
        else {
            /* Three registers of the same length */
            uint32_t A = (instr >> 8) & 0xf;
            uint32_t B = (instr >> 4) & 1;
            switch (A) {
            case 0:
                add_str(B ? "vqadd" : "vhadd");
                break;
            case 1:
                if (!B) {
                    add_str("vrhadd");
                }
                else {
                    no_dt = 1;
                    if (!U) {
                        switch (sz) {
                        case 0: add_str("vand"); break;
                        case 1: add_str("vbic"); break;
                        case 2: add_str("vorr"); break;
                        case 3: add_str("vorn"); break;
                        }
                    }
                    else {
                        switch (sz) {
                        case 0: add_str("veor"); break;
                        case 1: add_str("vbsl"); break;
                        case 2: add_str("vbit"); break;
                        case 3: add_str("vbif"); break;
                        }
                    }
                }
                break;
            case 2:
                add_str(B ? "vqsub" : "vhsub");
                break;
            case 3:
                add_str(B ? "vcge" : "vcgt");
                break;
            case 4:
                add_str(B ? "vqshl" : "vshl");
                break;
            case 5:
                add_str(B ? "vqrshl" : "vrshl");
                break;
            case 6:
                add_str(B ? "vmin" : "vmax");
                break;
            case 7:
                add_str(B ? "vaba" : "vabd");
                break;
            case 8:
                fmt = 'i';
                if (!B) {
                    add_str(U ? "vsub" : "vadd");
                }
                else {
                    add_str(U ? "vceq" : "vtst");
                }
                break;
            case 9:
                add_str(B ? "vmul" : "vmla");
                break;
            case 10:
                add_str(B ? "vpmin" : "vpmax");
                break;
            case 11:
                fmt = 'i';
                if (!B) {
                    add_str(U ? "vqrdmulh" : "vqdmulh");
                }
                else if (!U) {
                    add_str("vpadd");
                }
                break;
            case 13:
                if (!B) {
                    if (!U) {
                        add_str(sz & 2 ? "vsub" : "vqdmulh");
                    }
                    else {
                        add_str(sz & 2 ? "vabd" : "vpadd");
                    }
                }
                else {
                    if (!U) {
                        add_str(instr & (1 << 6) ? "vmls" : "vmla");
                    }
                    else {
                        add_str("vmul");
                    }
                }
                fmt = 'f';
                sz = (sz & 1) + 2;
                break;
            case 14:
                if (!B) {
                    if (!U) {
                        add_str(sz & 2 ? "" : "vceq");
                    }
                    else {
                        add_str(sz & 2 ? "vcgt" : "vcge");
                    }
                }
                else {
                    if (!U) {
                        add_str("");
                    }
                    else {
                        add_str(sz & 2 ? "vacgt" : "vacge");
                    }
                }
                fmt = 'f';
                sz = (sz & 1) + 2;
                break;
            case 15:
                if (!B) {
                    if (!U) {
                        add_str(sz & 2 ? "vmin" : "vmax");
                    }
                    else {
                        add_str(sz & 2 ? "vpmin" : "vpmax");
                    }
                }
                else {
                    if (!U) {
                        add_str(sz & 2 ? "vrsqrts" : "vrecps");
                    }
                    else {
                        add_str("");
                    }
                }
                fmt = 'f';
                sz = (sz & 1) + 2;
                break;
            }
        }
        if (buf_pos > 0) {
            if (!no_dt) {
                add_char('.');
                if (fmt) add_char(fmt);
                else add_char(U ? 'u' : 's');
                add_dec_uint32(8 << sz);
            }
            add_char(' ');
            add_char(Q ? 'q' : 'd');
            add_dec_uint32(vd);
            add_str(", ");
            add_char(Q ? 'q' : 'd');
            add_dec_uint32(vn);
            add_str(", ");
            add_char(Q ? 'q' : 'd');
            add_dec_uint32(vm);
            return;
        }
    }

    if ((instr & 0xfeb80090) == 0xf2800010) {
        /* VMOV (immediate) */
        int Q = (instr & (1 << 6)) != 0;
        int op = (instr & (1 << 5)) != 0;
        uint32_t vd = (instr >> 12) & 0xf;
        if (instr & (1 << 22)) vd |= 0x10;
        if (Q) vd /= 2;
        if ((instr & 0x00000900) == 0x00000100 || (instr & 0x00000d00) == 0x00000900) {
            add_str(op ? "vbic" : "vorr");
        }
        else if (op && (instr & 0x00000e00) == 0x00000e00) {
            add_str("vmvn");
        }
        else {
            add_str("vmov");
        }
        add_str(Q ? ".i64 q" : ".i32 d");
        add_dec_uint32(vd);
        add_str(", #");
        add_dec_uint64(adv_simd_expand_imm(instr));
        return;
    }
}

static void disassemble_advanced_simd_load_store(uint32_t instr) {
    if ((instr & 0xffb00000) == 0xf4000000) {
        uint32_t type = (instr >> 8) & 0xf;
        uint32_t size = (instr >> 6) & 3;
        uint32_t align = (instr >> 4) & 3;
        int D = (instr & (1 << 22)) != 0;
        uint32_t vd = (instr >> 12) & 0xf;
        if (D) vd |= 0x10;
        add_str("vst4.");
        add_dec_uint32(8 << size);
        add_str(" {d");
        if (type == 0) {
            add_dec_uint32(vd);
            add_str("-d");
            add_dec_uint32(vd + 3);
        }
        else if (type == 1) {
            add_dec_uint32(vd);
            add_str(",d");
            add_dec_uint32(vd + 2);
            add_str(",d");
            add_dec_uint32(vd + 4);
            add_str(",d");
            add_dec_uint32(vd + 6);
        }
        else {
            buf_pos = 0;
        }
        if (buf_pos > 0) {
            uint32_t rm = instr & 0xf;
            add_str("}, [");
            add_reg_name((instr >> 16) & 0xf);
            if (align) {
                add_char('@');
                add_dec_uint32(21 << align);
            }
            if (rm == 0xf) {
                add_char(']');
            }
            else if (rm == 0xd) {
                add_str("]!");
            }
            else {
                add_str("], ");
                add_reg_name(rm);
            }
            return;
        }
    }
}

static void disassemble_vfp_other_data_processing_instr(uint32_t instr, const char * cond) {
    uint32_t op2 = (instr >> 16) & 0xf;
    int T = (instr & (1 << 7)) != 0;
    int sz = (instr & (1 << 8)) != 0;
    uint32_t vd = (instr >> 12) & 0xf;
    uint32_t vm = instr & 0xf;

    if (sz) {
        if (instr & (1 << 5)) vm |= 0x10;
        if (instr & (1 << 22)) vd |= 0x10;
    }
    else {
        vm *= 2;
        vd *= 2;
        if (instr & (1 << 5)) vm++;
        if (instr & (1 << 22)) vd++;
    }

    if (instr & (1 << 6)) {
        switch (op2) {
        case 0:
            add_str(T ? "vabs" : "vmov");
            break;
        case 1:
            add_str(T ? "vsqrt" : "vneg");
            break;
        case 2:
        case 3:
            /* VCVTB, VCVTT (between half-precision and single-precision, VFP) */
            add_str("vcvt");
            add_char(T ? 't' : 'b');
            add_str(cond);
            add_str(instr & (1 << 16) ? ".f16.f32 s" : ".f32.f16 s");
            add_dec_uint32(vd);
            add_str(", s");
            add_dec_uint32(vm);
            return;
        case 4:
        case 5:
            /* VCMP, VCMPE */
            add_str("vcmp");
            if (T) add_char('e');
            add_str(sz ? ".f64 d" : ".f32 s");
            add_dec_uint32(vd);
            if (instr & (1 << 16)) {
                add_str(", #0.0");
            }
            else {
                add_str(sz ? ", d" : ", s");
                add_dec_uint32(vm);
            }
            return;
        case 7:
            /* VCVT (between double-precision and single-precision) */
            add_str("vcvt");
            add_str(cond);
            if (sz) {
                vd = ((instr >> 12) & 0xf) * 2;
                if (instr & (1 << 22)) vd++;
            }
            else {
                vd = (instr >> 12) & 0xf;
                if (instr & (1 << 22)) vd |= 0x10;
            }
            add_str(sz ? ".f32.f64 s" : ".f64.f32 d");
            add_dec_uint32(vd);
            add_str(sz ? ", d" : ", s");
            add_dec_uint32(vm);
            return;
        case 8:
            /* VCVT, VCVTR (between floating-point and integer (to float), VFP) */
            add_str("vcvt");
            add_str(cond);
            add_str(sz ? ".f64" : ".f32");
            add_str(T ? ".s32" : ".u32");
            add_str(sz ? " d" : " s");
            add_dec_uint32(vd);
            add_str(", s");
            vm = (instr & 0xf) * 2;
            if (instr & (1 << 5)) vm++;
            add_dec_uint32(vm);
            return;
        case 10:
        case 11:
            /* VCVT (between floating-point and fixed-point (to float), VFP) */
            add_str("vcvt");
            add_str(cond);
            add_str(sz ? ".f64" : ".f32");
            if (op2 & 1) {
                add_str(T ? ".u32" : ".u16");
            }
            else {
                add_str(T ? ".s32" : ".s16");
            }
            add_str(sz ? " d" : " s");
            add_dec_uint32(vd);
            add_str(sz ? ", d" : ", s");
            add_dec_uint32(vd);
            add_str(", #");
            vm = (instr & 0xf) * 2;
            if (instr & (1 << 5)) vm++;
            vm = (op2 & 1 ? 32 : 16) - vm;
            add_dec_uint32(vm);
            return;
        case 12:
        case 13:
            /* VCVT, VCVTR (between floating-point and integer (to integer), VFP) */
            add_str("vcvt");
            if (!T) add_char('r');
            add_str(cond);
            add_str(op2 == 12 ? ".u32" : ".s32");
            add_str(sz ? ".f64" : ".f32");
            add_str(" s");
            vd = ((instr >> 12) & 0xf) * 2;
            if (instr & (1 << 22)) vd++;
            add_dec_uint32(vd);
            add_str(sz ? ", d" : ", s");
            add_dec_uint32(vm);
            return;
        case 14:
        case 15:
            /* VCVT (between floating-point and fixed-point (to fixed), VFP) */
            add_str("vcvt");
            add_str(cond);
            if (op2 & 1) {
                add_str(T ? ".u32" : ".u16");
            }
            else {
                add_str(T ? ".s32" : ".s16");
            }
            add_str(sz ? ".f64" : ".f32");
            add_str(sz ? " d" : " s");
            add_dec_uint32(vd);
            add_str(sz ? ", d" : ", s");
            add_dec_uint32(vd);
            add_str(", #");
            vm = (instr & 0xf) * 2;
            if (instr & (1 << 5)) vm++;
            vm = (op2 & 1 ? 32 : 16) - vm;
            add_dec_uint32(vm);
            return;
        }
        add_str(cond);
        add_str(sz ? ".f64 d" : ".f32 s");
        add_dec_uint32(vd);
        add_str(sz ? ", d" : ", s");
        add_dec_uint32(vm);
    }
    else {
        /* VMOV (immediate) */
        uint32_t imm = ((instr >> 12) & 0xf0) | (instr & 0xf);
        add_str("vmov");
        add_str(cond);
        add_str(sz ? ".f64 d" : ".f32 s");
        add_dec_uint32(vd);
        add_str(", #");
        if (!sz) {
            uint32_t v = vfp_expand_imm32(imm);
            add_flt_uint32(v);
            add_str(" ; 0x");
            add_hex_uint32(v);
        }
        else {
            uint64_t v = vfp_expand_imm64(imm);
            add_flt_uint64(v);
            add_str(" ; 0x");
            add_hex_uint64(v);
        }
    }
}

static void disassemble_vfp_data_processing_instr(uint32_t instr, const char * cond) {
    uint32_t op1 = (instr >> 20) & 0xf;
    uint32_t vn = (instr >> 16) & 0xf;
    uint32_t vd = (instr >> 12) & 0xf;
    uint32_t vm = instr & 0xf;

    switch (op1) {
    case 0:
    case 4:
        add_str(instr & (1 << 6) ? "vmls" : "vmla");
        break;
    case 1:
    case 5:
        add_str(instr & (1 << 6) ? "vnmls" : "vnmla");
        break;
    case 2:
    case 6:
        add_str(instr & (1 << 6) ? "vnmul" : "vmul");
        break;
    case 3:
    case 7:
        add_str(instr & (1 << 6) ? "vsub" : "vadd");
        break;
    case 8:
    case 12:
        add_str(instr & (1 << 6) ? "" : "vdiv");
        break;
    case 11:
    case 15:
        disassemble_vfp_other_data_processing_instr(instr, cond);
        return;
    }

    if (buf_pos > 0) {
        add_str(cond);
        add_str(instr & (1 << 8) ? ".f64" : ".f32");
        if (instr & (1 << 8)) {
            if (instr & (1 << 22)) vd |= 0x10;
            if (instr & (1 << 7)) vn |= 0x10;
            if (instr & (1 << 5)) vm |= 0x10;
            add_str(" d");
            add_dec_uint32(vd);
            add_str(", d");
            add_dec_uint32(vn);
            add_str(", d");
            add_dec_uint32(vm);
        }
        else {
            vd *= 2;
            vn *= 2;
            vm *= 2;
            if (instr & (1 << 22)) vd |= 1;
            if (instr & (1 << 7)) vn |= 1;
            if (instr & (1 << 5)) vm |= 1;
            add_str(" s");
            add_dec_uint32(vd);
            add_str(", s");
            add_dec_uint32(vn);
            add_str(", s");
            add_dec_uint32(vm);
        }
    }
}

static void disassemble_coprocessor_instr(uint32_t instr, const char * cond, unsigned cond_code) {
    if (cond_code != 15 && (instr & 0x0f000e10) == 0x0e000a00) {
        disassemble_vfp_data_processing_instr(instr, cond);
        if (buf_pos > 0) return;
    }

    if ((instr & 0x0e000000) == 0x0c000000) {
        int P = (instr & (1 << 24)) != 0;
        int U = (instr & (1 << 23)) != 0;
        int D = (instr & (1 << 22)) != 0;
        int W = (instr & (1 << 21)) != 0;
        int L = (instr & (1 << 20)) != 0;
        if ((instr & 0x00000e00) == 0x00000a00) {
            uint32_t rn = (instr >> 16) & 0xf;
            int V = (instr & (1 << 8)) != 0;
            if (!P && !U && !W) {
                if (D && (instr & 0x000000d0) == 0x00000010) {
                    /* 64-bit transfers between ARM core and extension registers */
                    int L = (instr & (1 << 20)) != 0;
                    int C = (instr & (1 << 8)) != 0;
                    uint32_t dn = instr & 0xf;
                    uint32_t sn = dn * 2;
                    if (instr & (1 << 5)) sn++;
                    add_str("vmov");
                    add_str(cond);
                    if (instr & (1 << 5)) dn |= 0x10;
                    add_char(' ');
                    if (L) {
                        add_reg_name((instr >> 12) & 0xf);
                        add_str(", ");
                        add_reg_name((instr >> 16) & 0xf);
                        add_str(", ");
                        if (!C) {
                            add_char('s');
                            add_dec_uint32(sn);
                            add_str(", s");
                            add_dec_uint32(sn + 1);
                        }
                        else {
                            add_char('d');
                            add_dec_uint32(dn);
                        }
                    }
                    else {
                        if (!C) {
                            add_char('s');
                            add_dec_uint32(sn);
                            add_str(", s");
                            add_dec_uint32(sn + 1);
                        }
                        else {
                            add_char('d');
                            add_dec_uint32(dn);
                        }
                        add_str(", ");
                        add_reg_name((instr >> 12) & 0xf);
                        add_str(", ");
                        add_reg_name((instr >> 16) & 0xf);
                    }
                }
            }
            else if (P && !W) {
                /* vldr, vstr */
                uint32_t dn = (instr >> 12) & 0xf;
                uint32_t imm8 = instr & 0xff;
                add_str(L ? "vldr" : "vstr");
                add_str(cond);
                add_char(' ');
                if (V) {
                    if (D) dn |= 0x10;
                    add_char('d');
                }
                else {
                    dn = (dn << 1) + D;
                    add_char('s');
                }
                add_dec_uint32(dn);
                add_str(", [");
                add_reg_name(rn);
                if (imm8 != 0) {
                    add_str(", #");
                    add_char(U ? '+' : '-');
                    add_dec_uint32(imm8 << 2);
                }
                add_char(']');
            }
            else if (P == U && W) {
                /* Undefined */
            }
            else {
                uint32_t dn = (instr >> 12) & 0xf;
                uint32_t imm8 = instr & 0xff;
                uint32_t dm = 0;
                if (D) dn |= 0x10;
                dm = dn + (V ? imm8 / 2 : imm8) - 1;
                if (W && rn == 13) {
                    add_str(L ? "vpop" : "vpush");
                    add_str(cond);
                    add_str(" {");
                }
                else {
                    add_str(L ? "vldm" : "vstm");
                    add_str(P ? "db" : "ia");
                    add_str(cond);
                    add_char(' ');
                    add_reg_name(rn);
                    if (W) add_char('!');
                    add_str(", {");
                }
                add_char(V ? 'd' : 's');
                add_dec_uint32(dn);
                if (dn != dm) {
                    add_char('-');
                    add_char(V ? 'd' : 's');
                    add_dec_uint32(dm);
                }
                add_char('}');
            }
        }
        else if (!P && !U && D && !W) {
            add_str(L ? "mrrc" : "mcrr");
            add_str(cond_code == 15 ? "2" : cond);
            add_char(' ');
            add_dec_uint32((instr >> 8) & 0xf);
            add_str(", ");
            add_dec_uint32((instr >> 4) & 0xf);
            add_str(", ");
            add_reg_name((instr >> 12) & 0xf);
            add_str(", ");
            add_reg_name((instr >> 16) & 0xf);
            add_str(", cr");
            add_dec_uint32(instr & 0xf);
        }
        else if (!P && !U && !D && !W) {
            /* Undefined */
        }
        else {
            uint32_t imm = instr & 0x000000ff;
            add_str(L ? "ldc" : "stc");
            if (cond_code == 15) add_char('2');
            if (D) add_char('l');
            if (cond_code != 15) add_str(cond);
            add_char(' ');
            add_dec_uint32((instr >> 8) & 0xf);
            add_str(", cr");
            add_dec_uint32((instr >> 12) & 0xf);
            add_str(", [");
            if ((instr & 0x000f0000) == 0x000f0000 && !P && U && !W) {
                add_str("pc], {");
                add_dec_uint32(imm);
                add_char('}');
            }
            else {
                add_reg_name((instr & 0x000f0000) >> 16);
                if (P) {
                    if (imm != 0) {
                        add_str(", #");
                        add_char(U ? '+' : '-');
                        add_dec_uint32(imm << 2);
                    }
                    add_char(']');
                    if (W && imm) add_char('!');
                }
                else if (W) {
                    add_char(']');
                    if (imm != 0) {
                        add_str(", #");
                        add_char(U ? '+' : '-');
                        add_dec_uint32(imm << 2);
                    }
                }
                else if (U) {
                    add_str("], {");
                    add_dec_uint32(imm);
                    add_char('}');
                }
                else {
                    add_str("], ???");
                }
            }
        }
        if (buf_pos > 0) return;
    }

    if ((instr & 0x0f900f50) == 0x0e800b10) {
        /* VDUP (ARM core register) */
        int Q = instr & (1 << 21);
        uint32_t vd = (instr >> 16) & 0xf;
        if (instr & (1 << 7)) vd |= 0x10;
        if (Q) vd /= 2;
        add_str("vdup");
        add_str(cond);
        if (instr & (1 << 22)) {
            add_str(".8");
        }
        else if (instr & (1 << 5)) {
            add_str(".16");
        }
        else {
            add_str(".32");
        }
        add_str(Q ? " q" : " d");
        add_dec_uint32(vd);
        add_str(", ");
        add_reg_name((instr >> 12) & 0xf);
        return;
    }

    if ((instr & 0x0fe00f90) == 0x0ee00a10) {
        int A = (instr & (1 << 20)) != 0;
        uint32_t rt = (instr >> 12) & 0xf;
        const char * reg = NULL;
        switch ((instr >> 16) & 0xf) {
        case 0: reg = "fpsid"; break;
        case 1: reg = "fpscr"; break;
        case 6: reg = "mvfr1"; break;
        case 7: reg = "mvfr0"; break;
        case 8: reg = "fpexc"; break;
        case 9: reg = "fpinst"; break;
        case 10: reg = "fpinst2"; break;
        }
        if (reg != NULL) {
            add_str(A ? "vmrs" : "vmsr");
            add_str(cond);
            add_char(' ');
            if (!A) {
                add_str(reg);
                add_str(", ");
            }
            if (rt == 15) add_str("APSR_nzcv");
            else add_reg_name(rt);
            if (A) {
                add_str(", ");
                add_str(reg);
            }
            return;
        }
    }

    if ((instr & 0x0f900f10) == 0x0e000b10) {
        uint32_t size = 32;
        uint32_t dn = (instr >> 16) & 0xf;
        add_str("vmov");
        add_str(cond);
        if (instr & (1 << 22)) size = 8;
        else if (instr & (1 << 5)) size = 16;
        if (instr & (1 << 7)) dn |= 0x10;
        if (size != 32) {
            add_char('.');
            add_dec_uint32(size);
        }
        add_str(" d");
        add_dec_uint32(dn);
        add_str(", ");
        add_reg_name((instr >> 12) & 0xf);
        return;
    }

    if ((instr & 0x0f100f10) == 0x0e100b10) {
        uint32_t size = 32;
        int U = (instr & (1 << 23)) != 0;
        uint32_t dn = (instr >> 16) & 0xf;
        add_str("vmov");
        add_str(cond);
        if (instr & (1 << 22)) size = 8;
        else if (instr & (1 << 5)) size = 16;
        if (instr & (1 << 7)) dn |= 0x10;
        if (size != 32) {
            add_char('.');
            add_char(U ? 'u' : 's');
            add_dec_uint32(size);
        }
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", ");
        add_str(" d");
        add_dec_uint32(dn);
        return;
    }

    if ((instr & 0x0fe00f10) == 0x0e000a10) {
        int L = (instr & (1 << 20)) != 0;
        uint32_t dn = (instr >> 15) & 0x1e;
        add_str("vmov");
        add_str(cond);
        if (instr & (1 << 7)) dn |= 1;
        add_char(' ');
        if (L) {
            add_reg_name((instr >> 12) & 0xf);
            add_str(", s");
            add_dec_uint32(dn);
        }
        else {
            add_char('s');
            add_dec_uint32(dn);
            add_str(", ");
            add_reg_name((instr >> 12) & 0xf);
        }
        return;
    }

    if ((instr & 0x0f000010) == 0x0e000010) {
        int A = (instr & (1 << 20)) != 0;
        add_str(A ? "mrc" : "mcr");
        add_str(cond_code == 15 ? "2" : cond);
        add_char(' ');
        add_dec_uint32((instr >> 8) & 0xf);
        add_str(", ");
        add_dec_uint32((instr >> 21) & 0x7);
        add_str(", ");
        add_reg_name((instr >> 12) & 0xf);
        add_str(", cr");
        add_dec_uint32((instr >> 16) & 0xf);
        add_str(", cr");
        add_dec_uint32(instr & 0xf);
        if (instr & 0x000000e0) {
            add_str(", ");
            add_dec_uint32((instr >> 5) & 0x7);
        }
        return;
    }

    if ((instr & 0x0f000010) == 0x0e000000) {
        add_str("cdp");
        add_str(cond_code == 15 ? "2" : cond);
        add_char(' ');
        add_dec_uint32((instr >> 8) & 0xf);
        add_str(", ");
        add_dec_uint32((instr >> 20) & 0xf);
        add_str(", cr");
        add_dec_uint32((instr >> 12) & 0xf);
        add_str(", cr");
        add_dec_uint32((instr >> 16) & 0xf);
        add_str(", cr");
        add_dec_uint32(instr & 0xf);
        if (instr & 0x000000e0) {
            add_str(", ");
            add_dec_uint32((instr >> 5) & 0x7);
        }
        return;
    }
}

static void disassemble_unconditional_instr(uint32_t addr, uint32_t instr) {
    if ((instr & 0xfff10020) == 0xf1000000) {
        uint32_t imod = (instr >> 18) & 3;
        uint32_t mode = instr & 0x1f;
        add_str("cps");
        if (imod >= 2) {
            add_str(imod == 2 ? "ie" : "id");
            add_char(' ');
            if (instr & (1 << 8)) add_char('a');
            if (instr & (1 << 7)) add_char('i');
            if (instr & (1 << 6)) add_char('f');
            if (instr & (1 << 17)) {
                add_str(", #");
                add_dec_uint32(mode);
            }
        }
        else {
            add_str(" #");
            add_dec_uint32(mode);
        }
        return;
    }

    if ((instr & 0xffff00f0) == 0xf1010000) {
        add_str("setend ");
        add_str(instr & 0x00000200 ? "be" : "le");
        return;
    }

    if ((instr & 0xfe000000) == 0xf2000000) {
        disassemble_advanced_simd_data_processing(instr);
        return;
    }

    if ((instr & 0xff100000) == 0xf4000000) {
        disassemble_advanced_simd_load_store(instr);
        return;
    }

    if ((instr & 0xfd700000) == 0xf4100000) {
        /* TODO: Unallocated memory hint */
        return;
    }

    if ((instr & 0xfd700000) == 0xf4500000) {
        int U = (instr & (1 << 23)) != 0;
        int reg = (instr & (1 << 25)) != 0;
        add_str("pli [");
        add_reg_name((instr & 0x000f0000) >> 16);
        if (!reg) {
            uint32_t offs = instr & 0xfff;
            add_str(", #");
            add_char(U ? '+' : '-');
            add_dec_uint32(offs);
        }
        else {
            add_str(", ");
            add_char(U ? '+' : '-');
            add_shift(instr, 0);
        }
        add_char(']');
        return;
    }

    if ((instr & 0xfd300000) == 0xf5100000) {
        int U = (instr & (1 << 23)) != 0;
        int R = (instr & (1 << 22)) != 0;
        int reg = (instr & (1 << 25)) != 0;
        add_str("pld");
        if (!R) add_char('w');
        add_str(" [");
        add_reg_name((instr & 0x000f0000) >> 16);
        if (!reg) {
            uint32_t offs = instr & 0xfff;
            if (offs) {
                add_str(", #");
                add_char(U ? '+' : '-');
                add_dec_uint32(offs);
            }
        }
        else {
            add_str(", ");
            add_char(U ? '+' : '-');
            add_shift(instr, 0);
        }
        add_char(']');
        return;
    }

    if ((instr & 0xfff00000) == 0xf5700000) {
        switch ((instr & 0x000000f0) >> 4) {
        case 1:
            add_str("clrex");
            return;
        case 4:
            add_str("dsb");
            break;
        case 5:
            add_str("dmb");
            break;
        case 6:
            add_str("isb");
            break;
        default:
            return;
        }
        add_char(' ');
        switch (instr & 0x0000000f) {
        case 15: add_str("sy"); break;
        case 14: add_str("st"); break;
        case 11: add_str("ish"); break;
        case 10: add_str("ishst"); break;
        case  7: add_str("nsh"); break;
        case  6: add_str("nshst"); break;
        case  3: add_str("osh"); break;
        case  2: add_str("oshst"); break;
        default: add_dec_uint32(instr & 0x0000000f);
        }
        return;
    }

    if ((instr & 0xfe500000) == 0xf8400000) {
        add_str("srs");
        add_auto_inc_mode(instr, 0);
        add_str(" sp");
        if (instr & (1 << 21)) add_char('!');
        add_str(", #");
        add_dec_uint32(instr & 0x1f);
        return;
    }

    if ((instr & 0xfe500000) == 0xf8100000) {
        add_str("rfe");
        add_auto_inc_mode(instr, 0);
        add_char(' ');
        add_reg_name((instr >> 16) & 0xf);
        if (instr & (1 << 21)) add_char('!');
        return;
    }

    if ((instr & 0xfe000000) == 0xfa000000) {
        int32_t offset = instr & 0x00ffffff;
        if (offset & 0x00800000) offset |= ~0x00ffffff;
        offset = offset << 2;
        if (instr & (1 << 24)) offset |= 2;
        add_str("blx");
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
        add_hex_uint32(addr + offset + 8);
        return;
    }
}

static void disassemble_data_instr(uint32_t instr, const char * cond) {
    uint32_t op_code = (instr >> 21) & 0xf;
    int I = (instr & (1 << 25)) != 0;
    int S = (instr & (1 << 20)) != 0;
    uint32_t rn = (instr >> 16) & 0xf;
    uint32_t rd = (instr >> 12) & 0xf;
    int no_shift_name = 1;

    if ((instr & 0xffffffff) == 0xe1a00000) {
        add_str("nop");
        return;
    }

    if ((instr & 0x0fef0000) == 0x01a00000) {
        uint32_t shift_imm = (instr >> 7) & 0x1f;
        uint32_t shift_type = (instr >> 5) & 3;
        if ((instr & 0x00000010) != 0 || shift_imm != 0) {
            add_str(shift_names[shift_type]);
        }
        else if ((instr & 0x00000010) == 0 && shift_type == 3 && shift_imm == 0) {
            add_str("rrx");
        }
    }

    if (buf_pos == 0) {
        if (op_code >= 8 && op_code <= 11) {
            if (!S) return;
            S = 0;
        }
        add_str(op_names[op_code]);
        no_shift_name = 0;
    }

    if (S) add_char('s');
    add_str(cond);
    add_char(' ');
    if (op_code < 8 || op_code > 11) {
        add_reg_name(rd);
        add_str(", ");
    }
    if (op_code != 13 && op_code != 15) {
        add_reg_name(rn);
        add_str(", ");
    }

    if (I) {
        add_modifed_immediate_constant(instr & 0xfff);
    }
    else {
        /* Register and shift */
        add_shift(instr, no_shift_name);
    }
}

static void disassemble_misc_instr(uint32_t instr, const char * cond) {

    if ((instr & 0x0fffffd0) == 0x012fff10) {
        add_char('b');
        if (instr & 0x00000020) add_char('l');
        add_char('x');
        add_str(cond);
        add_char(' ');
        add_reg_name(instr & 0xf);
        return;
    }

    if ((instr & 0x0ff000f0) == 0x01200070) {
        uint32_t imm16 = (instr & 0xf) + ((instr &0xfff00) >> 4);
        add_str("bkpt");
        add_str(cond);
        add_str(" #");
        add_dec_uint32(imm16);
        return;
    }

    if ((instr & 0x0fff0000) == 0x03200000) {
        uint32_t op2 = instr & 0xff;
        if ((op2 & 0xf0) == 0xf0) {
            add_str("dbg");
            add_str(cond);
            add_str(" #");
            add_dec_uint32(op2 & 0xf);
            return;
        }
        switch (op2) {
        case 1: add_str("yield"); break;
        case 2: add_str("wfe"); break;
        case 3: add_str("wfi"); break;
        case 4: add_str("sev"); break;
        default: add_str("nop"); break;
        }
        add_str(cond);
        if (op2 > 4) {
            add_str(" #");
            add_dec_uint32(op2);
        }
        return;
    }

    if ((instr & 0x0fb000f0) == 0x01000000) {
        add_str("mrs");
        add_str(cond);
        add_char(' ');
        add_reg_name((instr & 0x0000f000) >> 12);
        add_str(", ");
        add_str(instr & (1 << 22) ? "spsr" : "cpsr");
        return;
    }

    if ((instr & 0x0db00000) == 0x01200000) {
        int R = (instr & (1 << 22)) != 0;
        uint32_t mask = (instr >> 16) & 0xf;
        if (R || mask) {
            add_str("msr");
            add_str(cond);
            add_char(' ');
            add_str(R ? "spsr" : "cpsr");
            add_char('_');
            if (mask & 8) add_char('f');
            if (mask & 4) add_char('s');
            if (mask & 2) add_char('x');
            if (mask & 1) add_char('c');
            add_str(", ");
            if (instr & (1 << 25)) {
                add_modifed_immediate_constant(instr & 0xfff);
                return;
            }
            if (instr & 0x000000f0) {
                buf_pos = 0;
            }
            else {
                add_reg_name(instr & 0xf);
                return;
            }
        }
    }

    if ((instr & 0x0ff000f0) == 0x01600010) {
        /* Count Leading Zeros */
        add_str("clz");
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", ");
        add_reg_name(instr & 0xf);
        return;
    }

    if ((instr & 0x0fb00000) == 0x03000000) {
        /* 16-bit immediate load */
        uint32_t imm = (instr & 0xfff) | ((instr & 0xf0000) >> 4);
        add_str(instr & (1 << 22) ? "movt" : "movw");
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", #");
        add_dec_uint32(imm);
        return;
    }

    if ((instr & 0x0fb000f0) == 0x01000090) {
        int B = (instr & (1 << 22)) != 0;
        add_str("swp");
        if (B) add_char('b');
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", ");
        add_reg_name(instr & 0xf);
        add_str(", [");
        add_reg_name((instr >> 16) & 0xf);
        add_char(']');
        return;
    }

    if ((instr & 0x0f8000f0) == 0x01800090) {
        int op = (instr >> 21) & 3;
        int L = (instr & (1 << 20)) != 0;
        add_str(L ? "ldrex" : "strex");
        switch (op) {
        case 0: break;
        case 1: add_char('d'); break;
        case 2: add_char('b'); break;
        case 3: add_char('h'); break;
        }
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        if (!L) {
            add_str(", ");
            add_reg_name(instr & 0xf);
        }
        add_str(", [");
        add_reg_name((instr >> 16) & 0xf);
        add_char(']');
        return;
    }

    if ((instr & 0x0e0000f0) == 0x00000090) {
        uint32_t op = (instr >> 21) & 7;
        int S = (instr & (1 << 20)) != 0;
        switch (op) {
        case 0:
            add_str("mul");
            break;
        case 1:
            add_str("mla");
            break;
        case 2:
            if (S) return;
            add_str("umaal");
            break;
        case 3:
            if (S) return;
            add_str("mls");
            break;
        case 4:
            add_str("umull");
            break;
        case 5:
            add_str("umlal");
            break;
        case 6:
            add_str("smull");
            break;
        case 7:
            add_str("smlal");
            break;
        }
        if (S) add_char('s');
        add_str(cond);
        add_char(' ');
        if (op == 2 || op >= 4) {
            add_reg_name((instr >> 12) & 0xf);
            add_str(", ");
        }
        add_reg_name((instr >> 16) & 0xf);
        add_str(", ");
        add_reg_name(instr & 0xf);
        add_str(", ");
        add_reg_name((instr >> 8) & 0xf);
        if (op == 1 || op == 3) {
            add_str(", ");
            add_reg_name((instr >> 12) & 0xf);
        }
        return;
    }

    if ((instr & 0x0ff00090) == 0x01000080) {
        add_str("smla");
        add_char(instr & (1 << 5) ? 't' : 'b');
        add_char(instr & (1 << 6) ? 't' : 'b');
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 16) & 0xf);
        add_str(", ");
        add_reg_name(instr & 0xf);
        add_str(", ");
        add_reg_name((instr >> 8) & 0xf);
        add_str(", ");
        add_reg_name((instr >> 12) & 0xf);
        return;
    }

    if ((instr & 0x0e000090) == 0x00000090) {
        /* Extra load/store instructions */
        int T = (instr & (1 << 24)) == 0 && (instr & (1 << 21));
        uint32_t op2 = (instr >> 5) & 3;
        if (op2 == 2 || (instr & (1 << 20))) {
            add_str("ldr");
        }
        else {
            add_str("str");
        }
        if (op2 == 1) {
            add_char('h');
        }
        else if (instr & (1 << 20)) {
            add_str(op2 == 2 ? "sb" : "sh");
        }
        else {
            add_char('d');
            T = 0;
        }
        if (T) add_char('t');
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", ");
        if (instr & (1 << 22)) {
            int P = (instr & (1 << 24)) != 0;
            int U = (instr & (1 << 23)) != 0;
            int W = (instr & (1 << 21)) != 0;
            uint32_t rn = (instr >> 16) & 0xf;
            uint32_t imm8 = ((instr >> 4) & 0xf0) | (instr & 0x0f);
            add_char('[');
            add_reg_name(rn);
            if (P) {
                if (W || imm8 != 0) {
                    add_str(",#");
                    add_char(U ? '+' : '-');
                    add_dec_uint32(imm8);
                }
                add_char(']');
                if (W) add_char('!');
            }
            else {
                add_str("], #");
                add_char(U ? '+' : '-');
                add_dec_uint32(imm8);
            }
        }
        else if (T) {
            int U = (instr & (1 << 23)) != 0;
            add_char('[');
            add_reg_name((instr >> 16) & 0xf);
            add_str("], ");
            add_char(U ? '+' : '-');
            add_reg_name(instr & 0xf);
        }
        else {
            int P = (instr & (1 << 24)) != 0;
            int U = (instr & (1 << 23)) != 0;
            int W = (instr & (1 << 21)) != 0;
            uint32_t rn = (instr >> 16) & 0xf;

            add_char('[');
            add_reg_name(rn);

            if (P) {
                add_str(", ");
                add_char(U ? '+' : '-');
                add_reg_name(instr & 0xf);
                add_char(']');
                if (W) add_char('!');
            }
            else {
                add_str("], ");
                add_char(U ? '+' : '-');
                add_reg_name(instr & 0xf);
            }
        }
        return;
    }
}

static void disassemble_media_instr(uint32_t instr, const char * cond) {
    if ((instr & 0x0f800000) == 0x06000000) {
        /* Parallel addition and subtraction */
        if ((instr & (1 << 22)) == 0) {
            /* signed */
            switch ((instr >> 20) & 3) {
            case 1: add_str("s"); break;
            case 2: add_str("q"); break;
            case 3: add_str("sh"); break;
            default: buf_pos = 0; return;
            }
        }
        else {
            /* unsigned */
            switch ((instr >> 20) & 3) {
            case 1: add_str("u"); break;
            case 2: add_str("uq"); break;
            case 3: add_str("uh"); break;
            default: buf_pos = 0; return;
            }
        }
        switch ((instr >> 5) & 7) {
        case 0: add_str("add16"); break;
        case 1: add_str("asx"); break;
        case 2: add_str("sax"); break;
        case 3: add_str("sub16"); break;
        case 4: add_str("add8"); break;
        case 7: add_str("sub8"); break;
        default: buf_pos = 0; return;
        }
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", ");
        add_reg_name((instr >> 16) & 0xf);
        add_str(", ");
        add_reg_name(instr & 0xf);
        return;
    }
    if ((instr & 0x0f800000) == 0x06800000) {
        /* Packing, unpacking, saturation, and reversal */
        switch ((instr >> 20) & 7) {
        case 0:
            if ((instr & (1 << 5)) == 0) {
                /* Pack Halfword */
                uint32_t imm = (instr >> 7) & 0x1f;
                add_str("pkh");
                add_str(instr & (1 << 6) ? "tb" : "bt");
                add_str(cond);
                add_char(' ');
                add_reg_name((instr >> 12) & 0xf);
                add_str(", ");
                add_reg_name((instr >> 16) & 0xf);
                add_str(", ");
                add_reg_name(instr & 0xf);
                if (imm) {
                    add_str(", ");
                    add_str(instr & (1 << 6) ? "asr" : "lsl");
                    add_str(" #");
                    add_dec_uint32(imm);
                }
            }
            if (((instr >> 5) & 7) == 5) {
                /* Select Bytes */
                add_str("sel");
                add_str(cond);
                add_char(' ');
                add_reg_name((instr >> 12) & 0xf);
                add_str(", ");
                add_reg_name((instr >> 16) & 0xf);
                add_str(", ");
                add_reg_name(instr & 0xf);
                return;
            }
            break;
        case 3:
            if (((instr >> 5) & 3) == 1) {
                /* Reverse */
                add_str("rev");
                if (instr & (1 << 7)) add_str("16");
                add_str(cond);
                add_char(' ');
                add_reg_name((instr >> 12) & 0xf);
                add_str(", ");
                add_reg_name(instr & 0xf);
                return;
            }
            break;
        case 7:
            if (((instr >> 5) & 3) == 1) {
                /* Reverse */
                add_str(instr & (1 << 7) ? "revsh" : "rbit");
                add_str(cond);
                add_char(' ');
                add_reg_name((instr >> 12) & 0xf);
                add_str(", ");
                add_reg_name(instr & 0xf);
                return;
            }
            break;
        }

        add_char(instr & (1 << 22) ? 'u' : 's');
        if ((instr & (1 << 21)) != 0 && ((instr >> 5) & 7) != 3) {
            /* Saturate */
            uint32_t imm = (instr >> 7) & 0x1f;
            add_str("sat");
            if (instr & (1 << 5)) add_str("16");
            add_str(cond);
            add_char(' ');
            add_reg_name((instr >> 12) & 0xf);
            add_str(", #");
            add_dec_uint32(((instr >> 16) & 0x1f) + 1);
            add_str(", ");
            add_reg_name(instr & 0xf);
            if (imm) {
                add_str(", ");
                add_str(instr & (1 << 6) ? "asr" : "lsl");
                add_str(" #");
                add_dec_uint32(imm);
            }
            return;
        }

        if (((instr >> 5) & 7) == 3) {
            /* Extend */
            uint32_t rm = (instr >> 16) & 0xf;
            uint32_t rt = (instr >> 10) & 3;
            add_str("xt");
            if (rm != 0xf) add_char('a');
            switch ((instr >> 20) & 3) {
            case 0: add_str("b16"); break;
            case 1: buf_pos = 0; return;
            case 2: add_str("b"); break;
            case 3: add_str("h"); break;
            }
            add_str(cond);
            add_char(' ');
            add_reg_name((instr >> 12) & 0xf);
            add_str(", ");
            if (rm != 0xf) {
                add_reg_name(rm);
                add_str(", ");
            }
            add_reg_name(instr & 0xf);
            if (rt) {
                add_str(", ");
                add_dec_uint32(rt);
            }
            return;

        }
        buf_pos = 0;
        return;
    }

    if ((instr & 0x0fa00070) == 0x07a00050) {
        /* Bit Field Extract */
        uint32_t lsb = (instr >> 7) & 0x1f;
        uint32_t width = ((instr >> 16) & 0x1f) + 1;
        add_char(instr & (1 << 22) ? 'u' : 's');
        add_str("bfx");
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        add_str(", ");
        add_reg_name(instr & 0xf);
        add_str(", #");
        add_dec_uint32(lsb);
        add_str(", #");
        add_dec_uint32(width);
        return;
    }

    if ((instr & 0x0fe00070) == 0x07c00010) {
        /* Bit Field Clear/Insert */
        uint32_t lsb = (instr >> 7) & 0x1f;
        uint32_t msb = (instr >> 16) & 0x1f;
        uint32_t rn = instr & 0xf;
        add_str(rn == 15 ? "bfc" : "bfi");
        add_str(cond);
        add_char(' ');
        add_reg_name((instr >> 12) & 0xf);
        if (rn != 15) {
            add_str(", ");
            add_reg_name(rn);
        }
        add_str(", #");
        add_dec_uint32(lsb);
        add_str(", #");
        add_dec_uint32(msb - lsb + 1);
        return;
    }
}

static void disassemble_load_store_instr(uint32_t instr, const char * cond) {
    int B = (instr & (1 << 22)) != 0;
    int L = (instr & (1 << 20)) != 0;
    int T = (instr & 0x0d200000) == 0x04200000;
    uint32_t rd = (instr & 0x0000f000) >> 12;

    if ((instr & 0x0fff0fff) == 0x052d0004) {
        add_str("push");
        add_str(cond);
        add_str(" {");
        add_reg_name(rd);
        add_char('}');
        return;
    }
    if ((instr & 0x0fff0fff) == 0x049d0004) {
        add_str("pop");
        add_str(cond);
        add_str(" {");
        add_reg_name(rd);
        add_char('}');
        return;
    }
    add_str(L ? "ldr" : "str");
    if (B) add_char('b');
    if (T) add_char('t');
    add_str(cond);
    add_char(' ');
    add_reg_name(rd);
    add_str(", ");
    if (T) {
        int R = (instr & (1 << 25)) != 0;
        int U = (instr & (1 << 23)) != 0;
        add_char('[');
        add_reg_name((instr >> 16) & 0xf);
        add_str("], ");
        if (!R) {
            add_char('#');
            add_char(U ? '+' : '-');
            add_dec_uint32(instr & 0xfff);
        }
        else {
            add_char(U ? '+' : '-');
            add_shift(instr, 0);
        }
    }
    else {
        add_addressing_mode(instr);
    }
}

static void disassemble_branch_and_block_data_transfer(uint32_t addr, uint32_t instr, const char * cond) {
    if ((instr & 0x0e000000) == 0x0a000000) { /* Branch */
        int L = (instr & 0x01000000) != 0;
        int32_t offset = instr & 0x00ffffff;
        if (offset & 0x00800000) offset |= ~0x00ffffff;
        offset = offset << 2;
        add_char('b');
        if (L) add_char('l');
        add_str(cond);
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
        add_hex_uint32(addr + offset + 8);
        return;
    }

    if ((instr & 0x0c000000) == 0x08000000) {
        unsigned i, j;
        if ((instr & 0x0fff0000) == 0x092d0000) {
            add_str("push");
            add_str(cond);
        }
        else if ((instr & 0x0fff0000) == 0x08bd0000) {
            add_str("pop");
            add_str(cond);
        }
        else {
            add_str(instr & (1 << 20) ? "ldm" : "stm");
            add_auto_inc_mode(instr, 1);
            add_str(cond);
            add_char(' ');
            add_reg_name((instr & 0x000f0000) >> 16);
            if (instr & (1 << 21)) add_char('!');
            add_char(',');
        }
        add_str(" {");
        for (i = 0, j = 0; i < 16; i++) {
            if (instr & (1 << i)) {
                if (j) add_char(',');
                add_reg_name(i);
                j++;
            }
        }
        add_char('}');
        if (instr & (1 << 22)) add_char('^');
        return;
    }
}

static void disassemble_supervisor_and_ext_load_store(uint32_t instr, const char * cond) {
    if ((instr & 0x0f000000) == 0x0f000000) {
        add_str("svc");
        add_str(cond);
        add_str(" 0x");
        add_hex_uint32(instr & 0x00ffffff);
        return;
    }
}

DisassemblyResult * disassemble_arm(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * params) {
    unsigned i;
    uint32_t instr = 0;
    uint8_t cond = 0;
    const char * cond_name = NULL;
    static DisassemblyResult dr;

    if (size < 4) return NULL;
    memset(&dr, 0, sizeof(dr));
    dr.size = 4;
    buf_pos = 0;
    for (i = 0; i < 4; i++) instr |= (uint32_t)*code++ << (i * 8);
    cond = (instr >> 28) & 0xf;
    cond_name = cond_names[cond];

    if ((instr & 0x0c000000) == 0x0c000000) {
        disassemble_coprocessor_instr(instr, cond_name, cond);
    }

    if (buf_pos == 0) {
        if (cond == 15) disassemble_unconditional_instr((uint32_t)addr, instr);
        else if ((instr & 0x0c000000) == 0x00000000) disassemble_misc_instr(instr, cond_name);
        else if ((instr & 0x0e000010) == 0x06000010) disassemble_media_instr(instr, cond_name);
        else if ((instr & 0x0c000000) == 0x04000000) disassemble_load_store_instr(instr, cond_name);
        else if ((instr & 0x0c000000) == 0x08000000) disassemble_branch_and_block_data_transfer((uint32_t)addr, instr, cond_name);
        else if ((instr & 0x0c000000) == 0x0c000000) disassemble_supervisor_and_ext_load_store(instr, cond_name);
    }

    if (buf_pos == 0 && (instr & 0x0c000000) == 0x00000000) {
        disassemble_data_instr(instr, cond_name);
    }

    if (buf_pos == 0) return NULL;

    buf[buf_pos] = 0;
    dr.text = buf;
    return &dr;
}
