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
 * "dynamic printf" service
 */

#include <tcf/config.h>

#if SERVICE_DPrintf && SERVICE_Expressions && SERVICE_Streams

#include <assert.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/cache.h>
#include <tcf/framework/json.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/streamsservice.h>
#include <tcf/services/runctrl.h>
#include <tcf/services/dprintf.h>

static const char * DPRINTF = "DPrintf";

typedef struct Buffer Buffer;
typedef struct Client Client;

struct Buffer {
    LINK link;
    char * buf;
    size_t done;
    size_t size;
};

struct Client {
    LINK link;
    LINK bufs;
    Channel * channel;
    VirtualStream * vstream;
    Buffer * queue;
};

#define link2buf(x)  ((Buffer *)((char *)(x) - offsetof(Buffer, link)))
#define link2client(x)  ((Client *)((char *)(x) - offsetof(Client, link)))

static LINK clients;

static char * buf = NULL;
static unsigned buf_pos = 0;
static unsigned buf_max = 0;

static Client * find_client(Channel * channel) {
    LINK * l;
    for (l = clients.next; l != &clients; l = l->next) {
        Client * client = link2client(l);
        if (client->channel == channel) return client;
    }
    return NULL;
}

static void add_ch(char ch) {
    if (buf_pos >= buf_max) {
        buf_max += 256;
        buf = (char *)tmp_realloc(buf, buf_max);
    }
    buf[buf_pos++] = ch;
}

void dprintf_expression(const char * fmt, Value * args, unsigned args_cnt) {
    unsigned fmt_pos = 0;
    unsigned arg_pos = 0;

    buf = NULL;
    buf_pos = 0;
    buf_max = 0;

    while (fmt[fmt_pos]) {
        char ch = fmt[fmt_pos];
        if (ch == 0) break;
        if (ch == '%' && arg_pos < args_cnt) {
            char arg_buf[256];
            char arg_fmt[256];
            unsigned pos = fmt_pos++;
            unsigned arg_len = 0;
            unsigned flag_l = 0;
            unsigned flag_h = 0;
            unsigned flag_L = 0;
            unsigned flag_j = 0;
            unsigned flag_z = 0;
            unsigned flag_t = 0;
            char fmt_ch = 0;
            Value * arg_val = args + arg_pos++;
            while (fmt[fmt_pos] && fmt_pos - pos < sizeof(arg_fmt)) {
                ch = fmt[fmt_pos];
                if (ch == 0) break;
                fmt_pos++;
                switch (ch) {
                case 'l': flag_l++; continue;
                case 'L': flag_L++; continue;
                case 'h': flag_h++; continue;
                case 'j': flag_j++; continue;
                case 'z': flag_z++; continue;
                case 't': flag_t++; continue;
                }
                if (ch == '%' || ch >= 'A') {
                    fmt_ch = ch;
                    break;
                }
            }
            if (fmt_ch != '%') {
                int64_t n = 0;
                uint64_t u = 0;
                double d = 0;
                memcpy(arg_fmt, fmt + pos, fmt_pos - pos);
                arg_fmt[fmt_pos - pos] = 0;
                switch (fmt_ch) {
                case 'd':
                case 'i':
                    if (arg_val->type_class == TYPE_CLASS_INTEGER || arg_val->type_class == TYPE_CLASS_ENUMERATION) {
                        if (value_to_signed(arg_val, &n) < 0) exception(errno);
                    }
                    else {
                        if (value_to_unsigned(arg_val, &u) < 0) exception(errno);
                        n = u;
                    }
                    if (flag_l > 1) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (long long)n);
                    else if (flag_l) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (long)n);
                    else if (flag_j) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (long long)n);
                    else if (flag_z) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (size_t)n);
                    else if (flag_t) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (ptrdiff_t)n);
                    else if (flag_h > 1) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (char)n);
                    else if (flag_h) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (short)n);
                    else snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (int)n);
                    break;
                case 'o':
                case 'u':
                case 'x':
                case 'X':
                    if (arg_val->type_class == TYPE_CLASS_INTEGER || arg_val->type_class == TYPE_CLASS_ENUMERATION) {
                        if (value_to_signed(arg_val, &n) < 0) exception(errno);
                    }
                    else {
                        if (value_to_unsigned(arg_val, &u) < 0) exception(errno);
                        n = u;
                    }
                    if (flag_l > 1) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (unsigned long long)n);
                    else if (flag_l) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (unsigned long)n);
                    else if (flag_j) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (unsigned long long)n);
                    else if (flag_z) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (size_t)n);
                    else if (flag_t) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (ptrdiff_t)n);
                    else if (flag_h > 1) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (unsigned char)n);
                    else if (flag_h) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (unsigned short)n);
                    else snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (unsigned int)n);
                    break;
                case 'c':
                case 'C':
                    if (value_to_signed(arg_val, &n) < 0) exception(errno);
                    snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (int)n);
                    break;
                case 'f':
                case 'F':
                case 'e':
                case 'E':
                case 'g':
                case 'G':
                case 'a':
                case 'A':
                    if (value_to_double(arg_val, &d) < 0) exception(errno);
                    if (flag_L) snprintf(arg_buf, sizeof(arg_buf), arg_fmt, (long double)d);
                    else snprintf(arg_buf, sizeof(arg_buf), arg_fmt, d);
                    break;
                default:
                    snprintf(arg_buf, sizeof(arg_buf), arg_fmt, arg_val->value);
                    break;
                }
                arg_len = strlen(arg_buf);
                if (buf_pos + arg_len >= buf_max) {
                    buf_max += arg_len + 256;
                    buf = (char *)tmp_realloc(buf, buf_max);
                }
                memcpy(buf + buf_pos, arg_buf, arg_len);
                buf_pos += arg_len;
                continue;
            }
        }
        add_ch(ch);
        fmt_pos++;
    }
    if (buf_pos > 0) {
        Channel * channel = cache_channel();
        if (channel != NULL) {
            Client * client = find_client(channel);
            if (client != NULL) {
                size_t done = 0;
                virtual_stream_add_data(client->vstream, buf, buf_pos, &done, 0);
                if (done < buf_pos) {
                    Buffer * b = (Buffer *)loc_alloc_zero(sizeof(Buffer));
                    b->size = buf_pos - done;
                    b->buf = (char *)loc_alloc(b->size);
                    memcpy(b->buf, buf + done, b->size);
                    if (list_is_empty(&client->bufs)) run_ctrl_lock();
                    list_add_last(&b->link, &client->bufs);
                }
            }
        }
    }
}

static void streams_callback(VirtualStream * stream, int event_code, void * args) {
    Client * client = (Client *)args;
    assert(stream == client->vstream);
    if (event_code == VS_EVENT_SPACE_AVAILABLE && !list_is_empty(&client->bufs)) {
        size_t done = 0;
        Buffer * b = link2buf(client->bufs.next);
        virtual_stream_add_data(stream, b->buf + b->done, b->size - b->done, &done, 0);
        b->done += done;
        if (b->done >= b->size) {
            list_remove(&b->link);
            if (list_is_empty(&client->bufs)) run_ctrl_unlock();
            loc_free(b->buf);
            loc_free(b);
        }
    }
}

static void read_open_args(InputStream * inp, const char * name, void * x) {
    json_skip_object(inp);
}

static void command_open(char * token, Channel * c) {
    char id[256];
    Client * client = find_client(c);

    json_read_struct(&c->inp, read_open_args, NULL);
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    if (client == NULL) {
        client = (Client *)loc_alloc_zero(sizeof(Client));
        virtual_stream_create(DPRINTF, NULL, 0x1000,
            VS_ENABLE_REMOTE_READ, streams_callback, client, &client->vstream);
        list_add_first(&client->link, &clients);
        list_init(&client->bufs);
        client->channel = c;
    }
    virtual_stream_get_id(client->vstream, id, sizeof(id));

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    json_write_string(&c->out, id);
    write_stream(&c->out, MARKER_EOA);
    write_stream(&c->out, MARKER_EOM);
}

static void free_client(Client * client) {
    virtual_stream_delete(client->vstream);
    list_remove(&client->link);
    while (!list_is_empty(&client->bufs)) {
        Buffer * bf = link2buf(client->bufs.next);
        list_remove(&bf->link);
        loc_free(bf->buf);
        loc_free(bf);
    }
    loc_free(client);
}

static void command_close(char * token, Channel * c) {
    Client * client = find_client(c);

    json_test_char(&c->inp, MARKER_EOM);

    if (client != NULL) free_client(client);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void channel_close_listener(Channel * c) {
    Client * client = find_client(c);
    if (client != NULL) free_client(client);
}

void ini_dprintf_service(Protocol * p) {
    list_init(&clients);
    add_command_handler(p, DPRINTF, "open", command_open);
    add_command_handler(p, DPRINTF, "close", command_close);
    add_channel_close_listener(channel_close_listener);
}

#endif /* SERVICE_DPrintf */
