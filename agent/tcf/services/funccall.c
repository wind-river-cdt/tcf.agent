/*******************************************************************************
 * Copyright (c) 2012 Wind River Systems, Inc. and others.
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
 * This module implements preparation of a new stack before calling a function.
 * This code is a stub. Downstream code will provide real implementation.
 */

#include <tcf/config.h>

#if ENABLE_Symbols && ENABLE_DebugContext

#include <assert.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/services/funccall.h>
#if defined(_WIN32)
#include <system/Windows/tcf/windbgcache.h>
#endif

static FunctionCallInfo * info = NULL;

static unsigned trace_cmds_max = 0;
static unsigned trace_cmds_cnt = 0;
static LocationExpressionCommand * trace_cmds = NULL;

static LocationExpressionCommand * add_command(int op) {
    LocationExpressionCommand * cmd = NULL;
    if (trace_cmds_cnt >= trace_cmds_max) {
        trace_cmds_max += 16;
        trace_cmds = (LocationExpressionCommand *)tmp_realloc(trace_cmds, trace_cmds_max * sizeof(LocationExpressionCommand));
    }
    cmd = trace_cmds + trace_cmds_cnt++;
    memset(cmd, 0, sizeof(*cmd));
    cmd->cmd = op;
    if (op == SFT_CMD_RD_MEM || op == SFT_CMD_WR_MEM) {
        cmd->args.mem.big_endian = info->scope.big_endian;
    }
    return cmd;
}

#if 0 /* Not used */
static LocationExpressionCommand * add_command_location(uint8_t * code, size_t code_size) {
    LocationExpressionCommand * cmd = NULL;
    cmd = add_command(SFT_CMD_LOCATION);
    cmd->args.loc.code_addr = code;
    cmd->args.loc.code_size = code_size;
    cmd->args.loc.reg_id_scope = info->scope;
    cmd->args.loc.addr_size =  info->scope.elf64? 64 : 32;
    return cmd;
}
#endif

static int get_stack_pointer_register_id(void) {
    switch (info->scope.machine) {
    case 3: /* EM_386 */
        return 4;
    case 62: /* EM_X86_64 */
        return 7;
    }
    return -1;
}

static int get_return_value_register_id(void) {
    switch (info->scope.machine) {
    case 3: /* EM_386 */
        return 0;
    case 62: /* EM_X86_64 */
        return 0;
    }
    return -1;
}

static RegisterDefinition * find_register(int id) {
    if (id < 0) return NULL;
    return get_reg_by_id(info->ctx, id, &info->scope);
}

static int c_call_cmds(void) {
    unsigned i;
    unsigned sp_offs = 0;
    unsigned word_size = info->scope.elf64 ? 8 : 4;
    Symbol * res_type = NULL;
    ContextAddress res_size = 0;
    int res_type_class = 0;

    RegisterDefinition * reg_rv = find_register(get_return_value_register_id());
    RegisterDefinition * reg_sp = find_register(get_stack_pointer_register_id());
    RegisterDefinition * reg_pc = get_PC_definition(info->ctx);

    if (reg_sp == NULL) {
        set_errno(ERR_OTHER, "Don't know stack pointer register");
        return -1;
    }
    if (reg_pc == NULL) {
        set_errno(ERR_OTHER, "Don't know instruction pointer register");
        return -1;
    }

    for (i = 0; i < info->args_cnt; i++) {
        const Symbol * s = info->args[info->args_cnt - i - 1];
        int type_class = TYPE_CLASS_INTEGER;
        /* If argument type is not given, assume 'int' */
        if (s != NULL && get_symbol_type_class(s, &type_class) < 0) return -1;
        switch (type_class) {
        case TYPE_CLASS_CARDINAL:
        case TYPE_CLASS_INTEGER:
        case TYPE_CLASS_POINTER:
        case TYPE_CLASS_ENUMERATION:
        case TYPE_CLASS_ARRAY:
        case TYPE_CLASS_COMPOSITE:
        case TYPE_CLASS_FUNCTION:
            /* Argument is one word, push it to the stack */
            sp_offs += word_size;
            add_command(SFT_CMD_RD_REG)->args.reg = reg_sp;
            add_command(SFT_CMD_NUMBER)->args.num = sp_offs;
            add_command(SFT_CMD_SUB);
            add_command(SFT_CMD_ARG)->args.arg_no = info->args_cnt - i - 1;
            add_command(SFT_CMD_WR_MEM)->args.mem.size = word_size;
            break;
        case TYPE_CLASS_REAL:
        case TYPE_CLASS_MEMBER_PTR:
        default:
            set_errno(ERR_OTHER, "Unsupported argument type");
            return -1;
        }
    }

    /* Push current PC to the stack as return address */
    sp_offs += reg_pc->size;
    add_command(SFT_CMD_RD_REG)->args.reg = reg_sp;
    add_command(SFT_CMD_NUMBER)->args.num = sp_offs;
    add_command(SFT_CMD_SUB);
    add_command(SFT_CMD_RD_REG)->args.reg = reg_pc;
    add_command(SFT_CMD_WR_MEM)->args.mem.size = reg_pc->size;

    /* Update stack pointer register */
    add_command(SFT_CMD_RD_REG)->args.reg = reg_sp;
    add_command(SFT_CMD_NUMBER)->args.num = sp_offs;
    add_command(SFT_CMD_SUB);
    add_command(SFT_CMD_WR_REG)->args.reg = reg_sp;

    /* Execute the call */
    add_command(SFT_CMD_FCALL);

    /* Get function return value */
    if (get_symbol_base_type(info->func, &res_type) < 0) return -1;
    if (get_symbol_size(res_type, &res_size) < 0) return -1;
    if (res_size == 0) return 0;
    if (get_symbol_type_class(res_type, &res_type_class) < 0) return -1;
    switch (res_type_class) {
    case TYPE_CLASS_CARDINAL:
    case TYPE_CLASS_INTEGER:
    case TYPE_CLASS_POINTER:
    case TYPE_CLASS_ENUMERATION:
    case TYPE_CLASS_ARRAY:
    case TYPE_CLASS_COMPOSITE:
    case TYPE_CLASS_FUNCTION:
        add_command(SFT_CMD_RD_REG)->args.reg = reg_rv;
        break;
    case TYPE_CLASS_REAL:
    case TYPE_CLASS_MEMBER_PTR:
    default:
        set_errno(ERR_OTHER, "Unsupported return type");
        return -1;
    }
    return 0;
}

static void save_registers(void) {
    unsigned cnt = 0;
    RegisterDefinition * r;
    RegisterDefinition * regs = get_reg_definitions(info->ctx);
    for (r = regs; r->name != NULL; r++) {
        if (r->dwarf_id < 0) continue;
        if (r->size == 0) continue;
        cnt++;
    }
    info->saveregs = (RegisterDefinition **)tmp_alloc(sizeof(RegisterDefinition *) * cnt);
    for (r = regs; r->name != NULL; r++) {
        if (r->dwarf_id < 0) continue;
        if (r->size == 0) continue;
        info->saveregs[info->saveregs_cnt++] = r;
    }
    assert(info->saveregs_cnt == cnt);
}

int get_function_call_location_expression(FunctionCallInfo * arg_info) {
    info = arg_info;
    trace_cmds_cnt = 0;
    trace_cmds_max = 0;
    trace_cmds = NULL;
#if !defined(_WIN32) || ENABLE_ELF
    if (c_call_cmds() < 0) return -1;
#else
    switch (info->scope.os_abi) {
    case CV_CALL_NEAR_C:
        /* Specifies a function-calling convention using a near right-to-left push.
         * The calling function clears the stack */
        if (c_call_cmds() < 0) return -1;
        break;
    default:
        set_errno(ERR_OTHER, "Unsupported calling convension code");
        return -1;
    }
#endif
    if (trace_cmds_cnt > 0) {
        save_registers();
        info->cmds = trace_cmds;
        info->cmds_cnt = trace_cmds_cnt;
        return 0;
    }
    set_errno(ERR_OTHER, "Calling functions is not supported");
    return -1;
}

#endif /* ENABLE_Symbols && ENABLE_DebugContext */
