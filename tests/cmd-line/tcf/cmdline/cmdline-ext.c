/*******************************************************************************
 * Copyright (c) 2011 Wind River Systems, Inc. and others.
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
#include <tcf/framework/json.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/exceptions.h>
#include <tcf/services/breakpoints.h>
#include <tcf/main/cmdline.h>
#include <tcf/cmdline/cmdline-ext.h>

static BreakpointInfo ** bp_list = NULL;
static unsigned bp_cnt = 0;
static unsigned bp_max = 0;
static char * client_id = NULL;

static char * get_bp_id(BreakpointAttribute * attrs) {
    static char id[256];
    while (attrs != NULL) {
        if (strcmp(attrs->name, BREAKPOINT_ID) == 0) {
            ByteArrayInputStream buf;
            InputStream * inp = create_byte_array_input_stream(&buf, attrs->value, strlen(attrs->value));
            json_read_string(inp, id, sizeof(id));
            if (read_stream(inp) != MARKER_EOS) exception(ERR_JSON_SYNTAX);
            return id;
        }
        attrs = attrs->next;
    }
    return NULL;
}

static void show_foreing_breakpoints(BreakpointInfo * bp, void * args) {
    BreakpointAttribute * attrs = get_breakpoint_attributes(bp);
    char * id = get_bp_id(attrs);
    /* Skip my own breakpoints */
    /* TODO: should use "ClientData" attribute to check breakpoint owner */
    if (id != NULL && strncmp(id, client_id, strlen(client_id)) == 0) return;
    printf(" *:");
    while (attrs != NULL) {
        printf(" %s: %s;", attrs->name, attrs->value);
        attrs = attrs->next;
    }
    printf("\n");
}

static int cmd_info(char * cmd) {
    if (strcmp(cmd, "break") == 0) {
        unsigned i;
        for (i = 0; i < bp_cnt; i++) {
            if (bp_list[i] != NULL) {
                BreakpointAttribute * attrs = get_breakpoint_attributes(bp_list[i]);
                printf("%2u:", i);
                while (attrs != NULL) {
                    printf(" %s: %s;", attrs->name, attrs->value);
                    attrs = attrs->next;
                }
                printf("\n");
            }
        }
        /* Show breakpoints from other clients */
        iterate_breakpoints(show_foreing_breakpoints, NULL);
    }
    else {
        fprintf(stderr, "invalid argument: '%s'\n", cmd);
    }
    return 0;
}

static void create_bp_attribute(BreakpointAttribute ** attrs, const char * name, const char * value) {
    BreakpointAttribute * a = (BreakpointAttribute *)loc_alloc_zero(sizeof(BreakpointAttribute));
    a->name = loc_strdup(name);
    a->value = loc_strdup(value);
    a->next = *attrs;
    *attrs = a;
}

static int cmd_breakpoint(char * cmd) {
    BreakpointAttribute * attrs = NULL;
    BreakpointInfo * bp = NULL;
    unsigned bp_id = 0;
    unsigned i = 0;
    char buf[256];

    while (*cmd == ' ') cmd++;
    if (*cmd == 0) {
        fprintf(stderr, "Cannot set breakpoint at current PC location - no thread is selected\n");
        errno = ERR_INV_CONTEXT;
        return -1;
    }

    if (bp_cnt <= bp_max) {
        bp_max += 8;
        bp_list = (BreakpointInfo **)loc_realloc(bp_list, sizeof(BreakpointInfo *) * bp_max);
    }
    bp_id = bp_cnt++;

    snprintf(buf, sizeof(buf), "\"%s-%u\"", client_id, bp_id);
    create_bp_attribute(&attrs, BREAKPOINT_ID, buf);
    create_bp_attribute(&attrs, BREAKPOINT_ENABLED, "true");

    while (cmd[i] && cmd[i] != ':') i++;

    if (cmd[i]) {
    }
    else {
        size_t len = strlen(cmd) + 8;
        char * str = (char *)tmp_alloc(len);
        snprintf(str, len, "\"%s\"", cmd);
        create_bp_attribute(&attrs, BREAKPOINT_LOCATION, str);
    }

    bp = create_breakpoint(attrs);
    bp_list[bp_id] = bp;
    printf("Breakpoint %u\n", bp_id);
    return 0;
}

static int cmd_delete(char * cmd) {
    unsigned id = 0;
    unsigned cnt = 0;

    while(*cmd == ' ') cmd++;
    if (*cmd == 0) {
        cnt = bp_cnt;
    }
    else {
        while (*cmd >= '0' && *cmd <= '9') {
            id = id * 10 + (unsigned)(*cmd++ - '0');
        }
        if (*cmd != 0 || id >= bp_cnt || bp_list[id] == NULL) {
            fprintf(stderr, "Invalid breakpoint ID\n");
            errno = ERR_INV_FORMAT;
            return -1;
        }
        cnt = id + 1;;
    }
    while (id < cnt) {
        if (bp_list[id] != NULL) {
            delete_breakpoint(bp_list[id]);
            bp_list[id] = NULL;
        }
        id++;
    }
    while (bp_cnt > 0 && bp_list[bp_cnt - 1] == NULL) bp_cnt--;
    return 0;
}

static int set_bp_enabled(char * cmd, int enabled) {
    unsigned id = 0;
    unsigned cnt = 0;

    while(*cmd == ' ') cmd++;
    if (*cmd == 0) {
        cnt = bp_cnt;
    }
    else {
        while (*cmd >= '0' && *cmd <= '9') {
            id = id * 10 + (unsigned)(*cmd++ - '0');
        }
        if (*cmd != 0 || id >= bp_cnt || bp_list[id] == NULL) {
            fprintf(stderr, "Invalid breakpoint ID\n");
            errno = ERR_INV_FORMAT;
            return -1;
        }
        cnt = id + 1;;
    }
    while (id < cnt) {
        if (bp_list[id] != NULL) {
            BreakpointAttribute * old_attrs = get_breakpoint_attributes(bp_list[id]);
            BreakpointAttribute * new_attrs = NULL;
            while (old_attrs != NULL) {
                if (strcmp(old_attrs->name, BREAKPOINT_ENABLED) != 0) {
                    create_bp_attribute(&new_attrs, old_attrs->name, old_attrs->value);
                }
                old_attrs = old_attrs->next;
            }
            create_bp_attribute(&new_attrs, BREAKPOINT_ENABLED, enabled ? "true" : "false");
            change_breakpoint_attributes(bp_list[id], new_attrs);
        }
        id++;
    }
    return 0;
}

static int cmd_disable(char * cmd) {
    return set_bp_enabled(cmd, 0);
}

static int cmd_enable(char * cmd) {
    return set_bp_enabled(cmd, 1);
}

void ini_cmdline_extension(void) {
    client_id = loc_strdup(create_uuid());
    add_cmdline_cmd("b", "set breakpoint", cmd_breakpoint);
    add_cmdline_cmd("break", "set breakpoint", cmd_breakpoint);
    add_cmdline_cmd("delete", "delete breakpoint(s)", cmd_delete);
    add_cmdline_cmd("disable", "disable breakpoint(s)", cmd_disable);
    add_cmdline_cmd("enable", "enable breakpoint(s)", cmd_enable);
    add_cmdline_cmd("info", "show information about various objects", cmd_info);
}
