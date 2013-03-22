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

#if SERVICE_Profiler

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
#include <tcf/services/profiler.h>

typedef struct {
    LINK link_ctx;
    ProfilerClass * cls;
} ProfilerRegistration;

typedef struct {
    LINK link_cfg;
    ProfilerClass * cls;
    void * obj;
} ProfilerInstance;

typedef struct {
    LINK link_all;
    char id[256];
    Channel * channel;
    unsigned params_cnt;
    ProfilerParams params;
    LINK list; /* List of ProfilerInstance */
} ProfilerConfiguration;

typedef struct {
    LINK list; /* List of ProfilerRegistration */
} ContextExtensionPF;

static const char * PROFILER = "Profiler";
static size_t context_extension_offset = 0;
static LINK cfgs;

#define EXT(ctx) (ctx ? ((ContextExtensionPF *)((char *)(ctx) + context_extension_offset)) : NULL)

#define link_all2cfg(x)  ((ProfilerConfiguration *)((char *)(x) - offsetof(ProfilerConfiguration, link_all)))
#define link_ctx2prf(x)  ((ProfilerRegistration *)((char *)(x) - offsetof(ProfilerRegistration, link_ctx)))
#define link_cfg2inst(x)  ((ProfilerInstance *)((char *)(x) - offsetof(ProfilerInstance, link_cfg)))

void add_profiler(Context * ctx, ProfilerClass * cls) {
    ContextExtensionPF * ext = EXT(ctx);
    ProfilerRegistration * prf = (ProfilerRegistration *)loc_alloc_zero(sizeof(ProfilerRegistration));
    if (list_is_empty(&ext->list)) list_init(&ext->list);
    list_add_last(&prf->link_ctx, &ext->list);
    assert(cls != NULL);
    prf->cls = cls;
}

static ProfilerConfiguration * find_cfg(Channel * c, const char * id) {
    LINK * l = cfgs.next;
    while (l != &cfgs) {
        ProfilerConfiguration * cfg = link_all2cfg(l);
        if (cfg->channel == c && strcmp(id, cfg->id) == 0) return cfg;
        l = l->next;
    }
    return NULL;
}

static void call_configure(Context * ctx) {
    if (ctx != NULL && !ctx->exited) {
        ContextExtensionPF * ext = EXT(ctx);
        LINK * k = cfgs.next;
        while (k != &cfgs) {
            ProfilerConfiguration * cfg = link_all2cfg(k);
            if (strcmp(ctx->id, cfg->id) == 0) {
                LINK * l = ext->list.next;
                while (l != &ext->list) {
                    ProfilerRegistration * prf = link_ctx2prf(l);
                    if (prf->cls->configure != NULL) {
                        ProfilerInstance * inst = NULL;
                        LINK * m = cfg->list.next;
                        while (m != &cfg->list) {
                            ProfilerInstance * x = link_cfg2inst(m);
                            if (x->cls == prf->cls) {
                                inst = x;
                                break;
                            }
                            m = m->next;
                        }
                        if (inst == NULL) {
                            inst = (ProfilerInstance *)loc_alloc_zero(sizeof(ProfilerInstance));
                            list_add_last(&inst->link_cfg, &cfg->list);
                            inst->cls = prf->cls;
                        }
                        inst->obj = inst->cls->configure(inst->obj, ctx, &cfg->params);
                    }
                    l = l->next;
                }
            }
            k = k->next;
        }
    }
}

static void call_read(Channel * c, Context * ctx) {
    LINK * k = cfgs.next;
    while (k != &cfgs) {
        unsigned cnt = 0;
        ProfilerConfiguration * cfg = link_all2cfg(k);
        if (cfg->channel == c && strcmp(ctx->id, cfg->id) == 0) {
            LINK * l = cfg->list.next;
            while (l != &cfg->list) {
                ProfilerInstance * inst = link_cfg2inst(l);
                if (inst->obj && inst->cls->read) {
                    if (cnt > 0) write_stream(&c->out, ',');
                    inst->cls->read(inst->obj, &c->out);
                    cnt++;
                }
                l = l->next;
            }
            break;
        }
        k = k->next;
    }
}

static void call_dispose(ProfilerConfiguration * cfg) {
    while (!list_is_empty(&cfg->list)) {
        ProfilerInstance * inst = link_cfg2inst(cfg->list.next);
        if (inst->obj && inst->cls->dispose) inst->cls->dispose(inst->obj);
        list_remove(&inst->link_cfg);
        loc_free(inst);
    }
}

static void read_cfg_param(InputStream * inp, const char * name, void * x) {
    ProfilerConfiguration * cfg = (ProfilerConfiguration *)x;
    if (strcmp(name, "FrameCnt") == 0) cfg->params.frame_cnt = json_read_ulong(inp);
    else if (strcmp(name, "MaxSamples") == 0) cfg->params.max_smaples = json_read_ulong(inp);
    else json_skip_object(inp);
    cfg->params_cnt++;
}

static void command_configure(char * token, Channel * c) {
    char id[256];
    ProfilerConfiguration * cfg = NULL;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    cfg = find_cfg(c, id);
    if (cfg == NULL) {
        cfg = (ProfilerConfiguration *)loc_alloc_zero(sizeof(ProfilerConfiguration));
        cfg->channel = c;
        list_init(&cfg->list);
        strlcpy(cfg->id, id, sizeof(cfg->id));
        list_add_last(&cfg->link_all, &cfgs);
    }
    else {
        cfg->params_cnt = 0;
        memset(&cfg->params, 0, sizeof(cfg->params));
    }
    json_read_struct(&c->inp, read_cfg_param, cfg);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    if (cfg->params_cnt > 0) {
        call_configure(id2ctx(id));
    }
    else {
        call_dispose(cfg);
        list_remove(&cfg->link_all);
        loc_free(cfg);
    }

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_read(char * token, Channel * c) {
    int error = 0;
    char id[256];
    Context * ctx = NULL;

    json_read_string(&c->inp, id, sizeof(id));
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    ctx = id2ctx(id);

    if (ctx == NULL) error = ERR_INV_CONTEXT;
    else if (ctx->exited) error = ERR_ALREADY_EXITED;

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, error);
    if (error) {
        write_stringz(&c->out, "null");
    }
    else {
        write_stream(&c->out, '[');
        call_read(c, ctx);
        write_stream(&c->out, ']');
        write_stream(&c->out, MARKER_EOA);
    }
    write_stream(&c->out, MARKER_EOM);
}

static void event_context_created(Context * ctx, void * args) {
    ContextExtensionPF * ext = EXT(ctx);
    if (list_is_empty(&ext->list)) list_init(&ext->list);
    call_configure(ctx);
}

static void event_context_exited(Context * ctx, void * args) {
    LINK * l;
    for (l = cfgs.next; l != &cfgs; l = l->next) {
        ProfilerConfiguration * cfg = link_all2cfg(l);
        if (strcmp(cfg->id, ctx->id) == 0) call_dispose(cfg);
    }
}

static void event_context_disposed(Context * ctx, void * args) {
    ContextExtensionPF * ext = EXT(ctx);
    LINK * l = ext->list.next;
    while (l != &ext->list) {
        ProfilerRegistration * prf = link_ctx2prf(l);
        l = l->next;
        list_remove(&prf->link_ctx);
        loc_free(prf);
    }
}

static void channel_close_listener(Channel * c) {
    LINK * l = cfgs.next;
    while (l != &cfgs) {
        ProfilerConfiguration * cfg = link_all2cfg(l);
        l = l->next;
        if (cfg->channel == c) {
            call_dispose(cfg);
            list_remove(&cfg->link_all);
            loc_free(cfg);
        }
    }
}

void ini_profiler_service(Protocol * proto) {
    static ContextEventListener listener = {
        event_context_created,
        event_context_exited,
        NULL,
        NULL,
        NULL,
        event_context_disposed
    };
    add_context_event_listener(&listener, NULL);
    add_channel_close_listener(channel_close_listener);
    context_extension_offset = context_extension(sizeof(ContextExtensionPF));
    add_command_handler(proto, PROFILER, "configure", command_configure);
    add_command_handler(proto, PROFILER, "read", command_read);
    list_init(&cfgs);
}

#endif /* SERVICE_Profiler */
