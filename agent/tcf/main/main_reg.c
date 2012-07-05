/*******************************************************************************
 * Copyright (c) 2007, 2012 Wind River Systems, Inc. and others.
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
 * TCF Registry main module.
 * TCF Registry is dumbed down version of TCF Agent that provides no services.
 * All it does is running TCF UDP auto-discovery protocol.
 */

#include <tcf/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <tcf/framework/asyncreq.h>
#include <tcf/framework/events.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/channel.h>
#include <tcf/framework/protocol.h>
#include <tcf/framework/proxy.h>
#include <tcf/services/discovery.h>

static const char * progname;

#if defined(_WRS_KERNEL)
int tcf_registry(void);
int tcf_registry(void) {
#else
int main(int argc, char **argv) {
    int c;
    int ind;
    const char * log_name = NULL;
#endif

    ini_mdep();
    ini_trace();
    ini_events_queue();
    ini_asyncreq();

#if defined(_WRS_KERNEL)

    progname = "tcf";
    open_log_file("-");
    log_mode = 0;

#else

    progname = argv[0];

    /* Parse arguments */
    for (ind = 1; ind < argc; ind++) {
        const char * s = argv[ind];
        if (*s != '-') {
            break;
        }
        s++;
        while ((c = *s++) != '\0') {
            switch (c) {
            case 'l':
            case 'L':
                if (*s == '\0') {
                    if (++ind >= argc) {
                        fprintf(stderr, "%s: error: no argument given to option '%c'\n", progname, c);
                        exit(1);
                    }
                    s = argv[ind];
                }
                switch (c) {
                case 'l':
                    if (parse_trace_mode(s, &log_mode) != 0) {
                        fprintf(stderr, "Cannot parse log level: %s\n", s);
                        exit(1);
                    }
                    break;

                case 'L':
                    log_name = s;
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

    discovery_start();

    /* Process events - must run on the initial thread since ptrace()
     * returns ECHILD otherwise, thinking we are not the owner. */
    run_event_loop();
    return 0;
}
