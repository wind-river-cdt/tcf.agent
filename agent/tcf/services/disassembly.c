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

#if SERVICE_Disassembly

#include <stdio.h>
#include <assert.h>
#include <tcf/framework/json.h>
#include <tcf/framework/context.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/cache.h>
#include <tcf/services/runctrl.h>
#include <tcf/services/symbols.h>
#include <tcf/services/linenumbers.h>
#include <tcf/services/memorymap.h>
#include <tcf/services/tcf_elf.h>
#include <tcf/services/disassembly.h>

#define MAX_INSTRUCTION_SIZE 8
#define DEFAULT_ALIGMENT     16

typedef struct {
    const char * isa;
    Disassembler * disassembler;
} DisassemblerInfo;

typedef struct {
    DisassemblerInfo * disassemblers;
    unsigned disassemblers_cnt;
    unsigned disassemblers_max;
} ContextExtensionDS;

typedef struct {
    Channel * c;
    char token[256];
    char id[256];
    ContextAddress addr;
    ContextAddress size;
    char * isa;
    int simplified;
    int pseudo_instr;
    int opcode_value;
} DisassembleCmdArgs;

static const char * DISASSEMBLY = "Disassembly";
static size_t context_extension_offset = 0;

#define EXT(ctx) (ctx ? ((ContextExtensionDS *)((char *)(ctx) + context_extension_offset)) : NULL)

static DisassemblerInfo * find_disassembler_info(Context * ctx, const char * isa) {
    if (isa != NULL) {
        unsigned i = 0;
        ContextExtensionDS * ext = EXT(ctx);
        while (i < ext->disassemblers_cnt) {
            if (strcmp(ext->disassemblers[i].isa, isa) == 0)
                return &ext->disassemblers[i];
            i++;
        }
    }
    return NULL;
}

static Disassembler * find_disassembler(Context * ctx, const char * isa) {
    DisassemblerInfo * i = find_disassembler_info(ctx, isa);
    return i ? i->disassembler : NULL;
}

void add_disassembler(Context * ctx, const char * isa, Disassembler disassembler) {
    DisassemblerInfo * i = NULL;
    ContextExtensionDS * ext = EXT(ctx);
    assert(ctx == context_get_group(ctx, CONTEXT_GROUP_CPU));
    if ((i = find_disassembler_info(ctx, isa)) == NULL) {
	if (ext->disassemblers_cnt >= ext->disassemblers_max) {
	    ext->disassemblers_max += 8;
	    ext->disassemblers = (DisassemblerInfo *)loc_realloc(ext->disassemblers,
                sizeof(DisassemblerInfo) * ext->disassemblers_max);
	}
	i = ext->disassemblers + ext->disassemblers_cnt++;
    } else {
	if (i->isa) loc_free(i->isa);
    }
    i->isa = loc_strdup(isa);
    i->disassembler = disassembler;
}

static void command_get_capabilities(char * token, Channel * c) {
    int error = 0;
    char id[256];
    Context * ctx = NULL;
    ContextExtensionDS * ext = NULL;
    unsigned i, j;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    ctx = id2ctx(id);

    if (ctx == NULL) error = ERR_INV_CONTEXT;
    else if (ctx->exited) error = ERR_ALREADY_EXITED;

    ctx = context_get_group(ctx, CONTEXT_GROUP_CPU);
    ext = EXT(ctx);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, error);
    write_stream(&c->out, '[');
    for (i = 0, j = 0; i < ext->disassemblers_cnt; i++) {
        if (j > 0) write_stream(&c->out, ',');
        write_stream(&c->out, '{');
        json_write_string(&c->out, "ISA");
        write_stream(&c->out, ':');
        json_write_string(&c->out, ext->disassemblers[i].isa);
        write_stream(&c->out, '}');
        j++;
    }
    write_stream(&c->out, ']');
    write_stream(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void get_isa(Context * ctx, ContextAddress addr, ContextISA * isa) {
    if (context_get_isa(ctx, addr, isa) < 0) {
        memset(isa, 0, sizeof(ContextISA));
    }
#if SERVICE_MemoryMap
    if (isa->size == 0) {
        unsigned i, j;
        MemoryMap * client_map = NULL;
        MemoryMap * target_map = NULL;
        Context * mem = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
        if (memory_map_get(mem, &client_map, &target_map) == 0) {
            isa->addr = addr;
            isa->size = ~(ContextAddress)0;
            for (j = 0; j < 2; j++) {
                MemoryMap * map = j ? target_map : client_map;
                for (i = 0; i < map->region_cnt; i++) {
                    MemoryRegion * r = map->regions + i;
                    ContextAddress x = r->addr;
                    ContextAddress y = r->addr + r->size;
                    if (x > addr && x < addr + isa->size) isa->size = x - addr;
                    if (y > addr && y < addr + isa->size) isa->size = y - addr;
                }
            }
        }
    }
#endif
}

static void disassemble_block(Context * ctx, OutputStream * out, uint8_t * mem_buf,
                              ContextAddress buf_addr, ContextAddress buf_size,
                              ContextAddress mem_size, ContextISA * isa,
                              DisassembleCmdArgs * args) {
    ContextAddress offs = 0;
    Disassembler * disassembler = NULL;
    Context * cpu = context_get_group(ctx, CONTEXT_GROUP_CPU);
    int disassembler_ok = 0;
    DisassemblerParams param;

    param.big_endian = ctx->big_endian;
    param.pseudo_instr = args->pseudo_instr;
    param.simplified = args->simplified;
    if (args->isa) {
        isa->isa = args->isa;
        isa->addr = args->addr;
        isa->size = args->size;
    }

    write_stream(out, '[');
    while (offs < buf_size && offs < mem_size) {
        ContextAddress addr = buf_addr + offs;
        ContextAddress size = mem_size - offs;
        DisassemblyResult * dr = NULL;
        if ((args->isa == NULL) && (addr < isa->addr || addr >= isa->addr + isa->size)) {
            get_isa(ctx, addr, isa);
            disassembler_ok = 0;
        }
        if (!disassembler_ok) {
            disassembler = find_disassembler(cpu, isa->isa);
            if (disassembler == NULL) disassembler = find_disassembler(cpu, isa->def);
            disassembler_ok = 1;
        }
        if (disassembler) dr = disassembler(mem_buf + (size_t)offs, addr, size, &param);
        if (dr == NULL) {
            static char buf[32];
            static DisassemblyResult dd;
            memset(&dd, 0, sizeof(dd));
            if (isa->alignment >= 4 && (addr & 0x3) == 0 && offs <= mem_size + 4) {
                unsigned i;
                uint32_t v = 0;
                for (i = 0; i < 4; i++) v |= (uint32_t)mem_buf[offs + i] << (i * 8);
                snprintf(buf, sizeof(buf), ".word 0x%08x", v);
                dd.size = 4;
            }
            else {
                snprintf(buf, sizeof(buf), ".byte 0x%02x", mem_buf[offs]);
                dd.size = 1;
            }
            dd.text = buf;
            dr = &dd;
        }
        if (offs > 0) write_stream(out, ',');
        write_stream(out, '{');
        json_write_string(out, "Address");
        write_stream(out, ':');
        json_write_uint64(out, addr);
        write_stream(out, ',');
        json_write_string(out, "Size");
        write_stream(out, ':');
        json_write_uint64(out, dr->size);
        write_stream(out, ',');
        json_write_string(out, "Instruction");
        write_stream(out, ':');
        write_stream(out, '[');
        write_stream(out, '{');
        json_write_string(out, "Type");
        write_stream(out, ':');
        json_write_string(out, "String");
        write_stream(out, ',');
        json_write_string(out, "Text");
        write_stream(out, ':');
        json_write_string(out, dr->text);
        write_stream(out, '}');
        write_stream(out, ']');
        if (args->opcode_value) {
            write_stream(out, ',');
            json_write_string(out, "OpcodeValue");
            write_stream(out, ':');
            json_write_binary(out, mem_buf + (size_t)offs, (size_t)dr->size);
        }
        write_stream(out, '}');
        offs += dr->size;
    }
    write_stream(out, ']');
}

#if SERVICE_LineNumbers
static void address_to_line_cb(CodeArea * area, void * args) {
    CodeArea ** p = (CodeArea **)args;
    if (*p == NULL || (*p)->start_address < area->start_address) {
        *p = (CodeArea *)tmp_alloc(sizeof(CodeArea));
        **p = *area;
    }
}
#endif

static void disassemble_cache_client(void * x) {
    DisassembleCmdArgs * args = (DisassembleCmdArgs *)x;

    int error = 0;
    Context * ctx = NULL;
    uint8_t * mem_buf = NULL;
    ContextAddress buf_addr = 0;
    ContextAddress buf_size = 0;
    size_t mem_size = 0;
    ByteArrayOutputStream buf;
    OutputStream * buf_out = create_byte_array_output_stream(&buf);
    OutputStream * out = &args->c->out;
    char * data = NULL;
    size_t size = 0;
    ContextISA isa;

    memset(&isa, 0, sizeof(isa));
    ctx = id2ctx(args->id);

    if (ctx == NULL) error = ERR_INV_CONTEXT;
    else if (ctx->exited) error = ERR_ALREADY_EXITED;

    if (!error) {
        ContextAddress sym_addr = 0;
        ContextAddress sym_size = 0;
        int sym_addr_ok = 0;
        int sym_size_ok = 0;
#if SERVICE_Symbols
        {
            Symbol * sym = NULL;
            if (find_symbol_by_addr(ctx, STACK_NO_FRAME, args->addr, &sym) == 0) {
                if (get_symbol_address(sym, &sym_addr) == 0) sym_addr_ok = 1;
                if (get_symbol_size(sym, &sym_size) == 0) sym_size_ok = 1;
            }
            if (sym_addr_ok && sym_addr <= args->addr) {
                if (args->addr - sym_addr >= 0x1000) {
                    sym_addr_ok = 0;
                    sym_size_ok = 0;
                }
                else if (sym_size_ok && sym_addr + sym_size > args->addr + args->size) {
                    sym_size = args->addr + args->size - sym_addr;
                }
            }
        }
#endif
#if SERVICE_LineNumbers
        if (!sym_addr_ok || !sym_size_ok) {
            CodeArea * area = NULL;
            address_to_line(ctx, args->addr, args->addr + 1, address_to_line_cb, &area);
            if (area != NULL) {
                sym_addr = area->start_address;
                sym_size = area->end_address - area->start_address;
                sym_addr_ok = 1;
                sym_size_ok = 1;
            }
        }
#endif
        if (sym_addr_ok && sym_size_ok && sym_addr <= args->addr && sym_addr + sym_size > args->addr) {
            buf_addr = sym_addr;
            buf_size = sym_size;
            mem_size = (size_t)sym_size;
        }
        else if (sym_addr_ok && sym_addr < args->addr) {
            get_isa(ctx, sym_addr, &isa);
            buf_addr = sym_addr;
            buf_size = args->addr + args->size - sym_addr;
            if (isa.max_instruction_size > 0) {
                mem_size = (size_t)(buf_size + isa.max_instruction_size);
            }
            else {
                mem_size = (size_t)(buf_size + MAX_INSTRUCTION_SIZE);
            }
        }
        else {
            /* Use default address alignment */
            get_isa(ctx, args->addr, &isa);
            if (isa.alignment > 0) {
                buf_addr = args->addr & ~(ContextAddress)(isa.alignment - 1);
            }
            else {
                buf_addr = args->addr & ~(ContextAddress)(DEFAULT_ALIGMENT - 1);
            }
            buf_size = args->addr + args->size - buf_addr;
            if (isa.max_instruction_size > 0) {
                mem_size = (size_t)(buf_size + isa.max_instruction_size);
            }
            else {
                mem_size = (size_t)(buf_size + MAX_INSTRUCTION_SIZE);
            }
        }
        mem_buf = (uint8_t *)loc_alloc(mem_size);
        if (context_read_mem(ctx, buf_addr, mem_buf, mem_size) < 0) error = errno;
        if (error) {
            MemoryErrorInfo info;
            if (context_get_mem_error_info(&info) < 0 || info.size_valid == 0) {
                mem_size = 0;
            }
            else {
                mem_size = info.size_valid;
                error = 0;
            }
        }
    }

    if (!error) disassemble_block(ctx, buf_out, mem_buf, buf_addr, buf_size,
                                  mem_size, &isa, args);

    cache_exit();

    get_byte_array_output_stream_data(&buf, &data, &size);

    write_stringz(out, "R");
    write_stringz(out, args->token);
    write_errno(out, error);
    if (size > 0) {
        size_t i = 0;
        while (i < size) write_stream(out, data[i++]);
    }
    else {
        write_string(out, "null");
    }
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);
    loc_free(data);
    loc_free(mem_buf);
}

static void safe_event_disassemble(void * x) {
    DisassembleCmdArgs * args = (DisassembleCmdArgs *)x;
    if (!is_channel_closed(args->c)) {
        cache_enter(disassemble_cache_client, args->c, args, sizeof(DisassembleCmdArgs));
    }
    channel_unlock(args->c);
    loc_free(args);
}

static void read_disassembly_params(InputStream * inp, const char * name, void * x) {
    DisassembleCmdArgs * args = (DisassembleCmdArgs *) x;

    if (strcmp(name, "ISA") == 0) {
        args->isa = json_read_alloc_string(inp);
    }
    else if (strcmp(name, "Simplified") == 0) {
        args->simplified = json_read_boolean(inp);
    }
    else if (strcmp(name, "Pseudo") == 0) {
        args->pseudo_instr = json_read_boolean(inp);
    }
    else if (strcmp(name, "OpcodeValue") == 0) {
        args->opcode_value =json_read_boolean(inp);
    }
    else {
        json_skip_object(inp);
    }
}

static void command_disassemble(char * token, Channel * c) {
    int error = 0;
    Context * ctx = NULL;
    DisassembleCmdArgs * args = (DisassembleCmdArgs *)loc_alloc_zero(sizeof(DisassembleCmdArgs));
    json_read_string(&c->inp, args->id, sizeof(args->id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args->addr = (ContextAddress)json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    args->size = (ContextAddress)json_read_uint64(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    json_read_struct(&c->inp, read_disassembly_params, args);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    ctx = id2ctx(args->id);
    if (ctx == NULL) error = ERR_INV_CONTEXT;
    else if (ctx->exited) error = ERR_ALREADY_EXITED;
    else if (context_get_group(ctx, CONTEXT_GROUP_PROCESS)->mem_access == 0) error = ERR_INV_CONTEXT;

    if (error != 0) {
        write_stringz(&c->out, "R");
        write_stringz(&c->out, token);
        write_errno(&c->out, error);
        write_stringz(&c->out, "null");
        write_stream(&c->out, MARKER_EOM);
        loc_free(args);
    }
    else {
        channel_lock(args->c = c);
        strlcpy(args->token, token, sizeof(args->token));
        post_safe_event(ctx, safe_event_disassemble, args);
    }
}

static void event_context_disposed(Context * ctx, void * args) {
    unsigned i;
    ContextExtensionDS * ext = EXT(ctx);
    for (i = 0; i < ext->disassemblers_cnt; i++) {
        loc_free(ext->disassemblers[i].isa);
    }
    loc_free(ext->disassemblers);
}

void ini_disassembly_service(Protocol * proto) {
    static ContextEventListener listener = {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        event_context_disposed
    };
    add_context_event_listener(&listener, NULL);
    context_extension_offset = context_extension(sizeof(ContextExtensionDS));
    add_command_handler(proto, DISASSEMBLY, "getCapabilities", command_get_capabilities);
    add_command_handler(proto, DISASSEMBLY, "disassemble", command_disassemble);
}

#endif /* SERVICE_Disassembly */
