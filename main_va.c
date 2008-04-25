/*******************************************************************************
 * Copyright (c) 2007, 2008 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials 
 * are made available under the terms of the Eclipse Public License v1.0 
 * which accompanies this distribution, and is available at 
 * http://www.eclipse.org/legal/epl-v10.html 
 *  
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * Agent main module.
 */

#include "mdep.h"
#define CONFIG_MAIN
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include "asyncreq.h"
#include "events.h"
#include "trace.h"
#include "myalloc.h"
#include "json.h"
#include "channel.h"
#include "protocol.h"
#include "discovery.h"
#include "expressions.h"
#include "errors.h"

static char * progname;
static Protocol * proto;
static ChannelServer * serv;
static ChannelServer * serv2;
static TCFBroadcastGroup * bcg;
static TCFSuspendGroup * spg;

static void channel_server_connecting(Channel * c) {
    trace(LOG_PROTOCOL, "channel server connecting");

    send_hello_message(c->client_data, c);
    discovery_channel_add(c);
    c->out.flush(&c->out);
}

static void channel_server_connected(Channel * c) {
    int i;

    trace(LOG_PROTOCOL, "channel server connected, peer services:");
    for (i = 0; i < c->peer_service_cnt; i++) {
        trace(LOG_PROTOCOL, "  %s", c->peer_service_list[i]);
    }
}

static void channel_server_receive(Channel * c) {
    handle_protocol_message(c->client_data, c);
}

static void channel_server_disconnected(Channel * c) {
    trace(LOG_PROTOCOL, "channel server disconnected");
    discovery_channel_remove(c);
    protocol_channel_closed(c->client_data, c);
}

static void initiate_redirect(Channel * c1, const char * token, const char * id) {
    PeerServer * ps;
    Channel * c2;
    Protocol * p1;
    Protocol * p2;

    ps = peer_server_find(id);
    if (ps == NULL) {
        write_stringz(&c1->out, "R");
        write_stringz(&c1->out, token);
        write_errno(&c1->out, ERR_UNKNOWN_PEER);
        c1->out.write(&c1->out, MARKER_EOM);
        return;
    }
    c2 = channel_connect(ps);
    if (c2 == NULL) {
        write_stringz(&c1->out, "R");
        write_stringz(&c1->out, token);
        write_errno(&c1->out, ERR_UNKNOWN_PEER);
        c1->out.write(&c1->out, MARKER_EOM);
        return;
    }
    protocol_channel_closed(c1->client_data, c1);
    protocol_release(c1->client_data);
    proxy_create(c1, c2);
    spg = suspend_group_alloc();
    channel_set_suspend_group(c1, spg);
    channel_set_suspend_group(c2, spg);
    channel_start(c2);
    write_stringz(&c1->out, "R");
    write_stringz(&c1->out, token);
    write_errno(&c1->out, 0);
    c1->out.write(&c1->out, MARKER_EOM);
}

static void channel_new_connection(ChannelServer * serv, Channel * c) {
    protocol_reference(proto);
    c->client_data = proto;
    c->connecting = channel_server_connecting;
    c->connected = channel_server_connected;
    c->receive = channel_server_receive;
    c->disconnected = channel_server_disconnected;
    channel_set_suspend_group(c, spg);
    channel_set_broadcast_group(c, bcg);
    c->redirecting = initiate_redirect;
    channel_start(c);
    protocol_channel_opened(proto, c);
}

static void add_proxy_props(PeerServer * ps) {
    peer_server_addprop(ps, loc_strdup("Name"), loc_strdup("TCF Proxy"));
    peer_server_addprop(ps, loc_strdup("Proxy"), loc_strdup(""));
}

static void became_discovery_master(void) {
    PeerServer * ps = channel_peer_from_url(DEFAULT_DISCOVERY_URL);

    if (ps == NULL) {
        trace(LOG_ALWAYS, "cannot parse url: %s\n", DEFAULT_DISCOVERY_URL);
        return;
    }
    add_proxy_props(ps);
    serv2 = channel_server(ps);
    if (serv2 == NULL) {
        trace(LOG_ALWAYS, "cannot create second TCF server\n");
        return;
    }
    serv2->new_conn = channel_new_connection;
}

#if defined(_WRS_KERNEL)
int tcf_va(void) {
#else   
int main(int argc, char ** argv) {
#endif
    int c;
    int ind;
    int ismaster;
    char * s;
    char * log_name = 0;
    char * url = "TCP:";
    PeerServer * ps;

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    ini_mdep();
    ini_trace();
    ini_asyncreq();
    ini_events_queue();
    ini_expression_library();

#if defined(_WRS_KERNEL)
    
    progname = "tcf";
    open_log_file("-");
    log_mode = 0;
    
#else
    
    progname = argv[0];

    /* Parse arguments */
    for (ind = 1; ind < argc; ind++) {
        s = argv[ind];
        if (*s != '-') {
            break;
        }
        s++;
        while ((c = *s++) != '\0') {
            switch (c) {
            case 'l':
            case 'L':
            case 's':
                if (*s == '\0') {
                    if (++ind >= argc) {
                        fprintf(stderr, "%s: error: no argument given to option '%c'\n", progname, c);
                        exit(1);
                    }
                    s = argv[ind];
                }
                switch (c) {
                case 'l':
                    log_mode = strtol(s, 0, 0);
                    break;

                case 'L':
                    log_name = s;
                    break;

                case 's':
                    url = s;
                    break;

                default:
                    fprintf(stderr, "%s: error: illegal option '%c'\n", progname, c);
                    exit(1);
                }
                s = "";
                break;

            default:
                fprintf(stderr, "%s: error: illegal option '%c'\n", progname, c);
                exit(1);
            }
        }
    }
    
    open_log_file(log_name);
    
#endif

    bcg = broadcast_group_alloc();
    spg = suspend_group_alloc();
    proto = protocol_alloc();
    ini_locator_service(proto);
    ini_diagnostics_service(proto);
    ismaster = discovery_start(became_discovery_master);

    ps = channel_peer_from_url(url);
    if (ps == NULL) {
        fprintf(stderr, "invalid server URL (-s option value): %s\n", url);
        exit(1);
    }
    add_proxy_props(ps);
    if (ismaster) {
        if (!strcmp(peer_server_getprop(ps, "TransportName", ""), "TCP") &&
                peer_server_getprop(ps, "Port", NULL) == NULL) {
            peer_server_addprop(ps, loc_strdup("Port"), loc_strdup(DISCOVERY_TCF_PORT));
        }
        serv = channel_server(ps);
        /* TODO: replace 'ps' with actual peer object created for the server */
        if (strcmp(peer_server_getprop(ps, "TransportName", ""), "TCP") ||
                strcmp(peer_server_getprop(ps, "Port", ""), DISCOVERY_TCF_PORT)) {
            became_discovery_master();
        }
    }
    else {
        serv = channel_server(ps);
    }
    if (serv == NULL) {
        fprintf(stderr, "cannot create TCF server\n");
        exit(1);
    }
    serv->new_conn = channel_new_connection;

    /* Process events - must run on the initial thread since ptrace()
     * returns ECHILD otherwise, thinking we are not the owner. */
    run_event_loop();
    return 0;
}