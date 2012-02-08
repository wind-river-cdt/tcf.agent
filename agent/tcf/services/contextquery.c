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

#include <tcf/config.h>

#if SERVICE_ContextQuery

#include <tcf/framework/json.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/contextquery.h>

typedef struct Comparator {
    char * attr_name;
    ContextQueryComparator * callback;
    struct Comparator * next;
} Comparator;

/* TODO: need hash table for faster search of query comparators */
static Comparator * comparators = NULL;

void add_context_query_comparator(const char * attr_name, ContextQueryComparator * callback) {
    Comparator * c = (Comparator *)loc_alloc_zero(sizeof(Comparator));
    c->attr_name = loc_strdup(attr_name);
    c->callback = callback;
    c->next = comparators;
    comparators = c;
}

static const char * CONTEXT_QUERY = "ContextQuery";

typedef struct Attribute {
    struct Attribute * next;
    struct Attribute * parent;
    char * name;
    char * value;
} Attribute;

static Attribute * attrs = NULL;
static char * str_buf = NULL;
static size_t str_pos = 0;
static size_t str_max = 0;
static int abs_path = 0;

static void add_char(char ch) {
    if (str_pos >= str_max) {
        str_max *= 2;
        str_buf = (char *)tmp_realloc(str_buf, str_max);
    }
    str_buf[str_pos++] = ch;
}

/* TODO: parse_context_query() should check for syntax errors and set errno */
void parse_context_query(const char * q) {
    str_pos = 0;
    str_buf = NULL;
    attrs = NULL;
    abs_path = 0;

    if (q == NULL) return;

    str_max = 64;
    str_buf = (char *)tmp_alloc(str_max);
    if ((abs_path = *q == '/') != 0) q++;
    while (*q) {
        Attribute * attr = (Attribute *)tmp_alloc_zero(sizeof(Attribute));
        for (;;) {
            str_pos = 0;
            while (*q) {
                if (*q == '/') {
                    q++;
                    break;
                }
                else if (*q == '=' || *q == ',') {
                    break;
                }
                else if (*q == '"') {
                    while (*q) {
                        if (*q == '"') {
                            q++;
                            break;
                        }
                        else if (*q == '\\') {
                            q++;
                            if (*q == '\\' || *q == '"') {
                                add_char(*q++);
                            }
                            else {
                                add_char('\\');
                            }
                        }
                        else {
                            add_char(*q++);
                        }
                    }
                }
                else {
                    add_char(*q++);
                }
            }
            add_char(0);
            if (*q == ',') {
                Attribute * a = attr;
                attr->value = tmp_strdup(str_buf);
                attr = (Attribute *)tmp_alloc_zero(sizeof(Attribute));
                attr->next = a;
                q++;
            }
            else if (attr->name == NULL && *q == '=') {
                attr->name = tmp_strdup(str_buf);
                q++;
            }
            else {
                attr->value = tmp_strdup(str_buf);
                break;
            }
        }
        attr->parent = attrs;
        attrs = attr;
    }
}

static int match_attribute(Context * ctx, const char * key, const char * val) {
    Comparator * c = comparators;
    while (c != NULL) {
        if (strcmp(c->attr_name, key) == 0) return c->callback(ctx, val);
        c = c->next;
    }
    return 0;
}

static int match(Context * ctx, Attribute * attr) {
    if (attr->name == NULL && strcmp(attr->value, "**") == 0) {
        if (attr->parent == NULL) return 1;
        while (ctx->parent != NULL) {
            ctx = ctx->parent;
            if (match(ctx, attr->parent)) return 1;
        }
        return 0;
    }
    if (attr->parent != NULL && (ctx->parent == NULL || !match(ctx->parent, attr->parent))) return 0;
    if (attr->parent == NULL && abs_path && ctx->parent != NULL) return 0;
    while (attr != NULL) {
        if (attr->name != NULL) {
            if (!match_attribute(ctx, attr->name, attr->value)) return 0;
        }
        else if (strcmp(attr->value, "*") != 0) {
            if (!match_attribute(ctx, "Name", attr->value)) return 0;
        }
        attr = attr->next;
    }
    return 1;
}

int run_context_query(Context * ctx) {
    if (attrs == NULL) return !abs_path;
    return match(ctx, attrs);
}

int context_query(Context * ctx, const char * query) {
    parse_context_query(query);
    return run_context_query(ctx);
}

static void command_query(char * token, Channel * c) {
    LINK * l;
    unsigned cnt = 0;
    char * query = json_read_alloc_string(&c->inp);
    if (read_stream(&c->inp) != 0) exception(ERR_JSON_SYNTAX);
    if (read_stream(&c->inp) != MARKER_EOM) exception(ERR_JSON_SYNTAX);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, 0);
    write_stream(&c->out, '[');

    parse_context_query(query);
    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (ctx->exited) continue;
        if (run_context_query(ctx)) {
            if (cnt > 0)  write_stream(&c->out, ',');
            json_write_string(&c->out, ctx->id);
        }
    }

    write_stream(&c->out, ']');
    write_stream(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
    loc_free(query);
}

static int cmp_id(Context * ctx, const char * v) {
    return strcmp(ctx->id, v) == 0;
}

static int cmp_name(Context * ctx, const char * v) {
    if (ctx->name != NULL) return strcmp(ctx->name, v) == 0;
    return strcmp(ctx->id, v) == 0;
}

void ini_context_query_service(Protocol * proto) {
    add_context_query_comparator("ID", cmp_id);
    add_context_query_comparator("Name", cmp_name);
    add_command_handler(proto, CONTEXT_QUERY, "query", command_query);
}

#else

#include <tcf/services/contextquery.h>

void add_context_query_comparator(const char * attr_name, ContextQueryComparator * callback) {}
void parse_context_query(const char * query) {}
int run_context_query(Context * ctx) { return 0; }
int context_query(Context * ctx, const char * query) { return query == NULL || *query == 0; }

#endif
