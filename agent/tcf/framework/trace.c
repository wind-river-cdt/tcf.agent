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

#include <tcf/config.h>
#include <tcf/framework/trace.h>

int log_mode = LOG_EVENTS | LOG_CHILD | LOG_WAITPID | LOG_CONTEXT | LOG_PROTOCOL;

#if ENABLE_Trace

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <tcf/framework/mdep-threads.h>

#if defined(_WIN32)
#elif defined(_WRS_KERNEL)
#elif defined(__SYMBIAN32__)
#else
#include <syslog.h>
#endif

FILE * log_file = NULL;

#define MAX_TRACE_MODES 40

struct trace_mode trace_mode_table[MAX_TRACE_MODES + 1] = {
    { LOG_ALLOC, "alloc", "memory allocation and deallocation" },
    { LOG_EVENTCORE, "eventcore", "main event queue" },
    { LOG_WAITPID, "waitpid", "waitpid() events" },
    { LOG_EVENTS, "events", "low-level debugger events" },
    { LOG_PROTOCOL, "protocol", "communication protocol" },
    { LOG_CONTEXT, "context", "debug context actions" },
    { LOG_CHILD, "children", "debug context children" },
    { LOG_DISCOVERY, "discovery", "discovery" },
    { LOG_ASYNCREQ, "asyncreq", "async I/O" },
    { LOG_PROXY, "proxy", "proxy state" },
    { LOG_TCFLOG, "tcflog", "proxy traffic" },
    { LOG_ELF, "elf", "ELF reader" },
    { LOG_LUA, "lua", "LUA interpreter" },
    { LOG_STACK, "stack", "stack trace service" },
    { LOG_PLUGIN, "plugin", "plugins" }
};

static pthread_mutex_t mutex;

int print_trace(int mode, const char * fmt, ...) {
    va_list ap;

    if (log_file == NULL) return 0;
    if (mode != LOG_ALWAYS && (log_mode & mode) == 0) return 0;

    va_start(ap, fmt);
    if (is_daemon()) {
#if defined(_WIN32)
#elif defined(_WRS_KERNEL)
#elif defined(__SYMBIAN32__)
#else
        vsyslog(LOG_MAKEPRI(LOG_DAEMON, LOG_INFO), fmt, ap);
#endif
    }
    else {
        struct timespec timenow;

        if (clock_gettime(CLOCK_REALTIME, &timenow)) {
            perror("clock_gettime");
            exit(1);
        }

        if ((errno = pthread_mutex_lock(&mutex)) != 0) {
            perror("pthread_mutex_lock");
            exit(1);
        }

        fprintf(log_file, "TCF %02d:%02d.%03d: ",
            (int)(timenow.tv_sec / 60 % 60),
            (int)(timenow.tv_sec % 60),
            (int)(timenow.tv_nsec / 1000000));
        vfprintf(log_file, fmt, ap);
        fprintf(log_file, "\n");
        fflush(log_file);

        if ((errno = pthread_mutex_unlock(&mutex)) != 0) {
            perror("pthread_mutex_unlock");
            exit(1);
        }
    }
    va_end(ap);
    return 1;
}

#endif /* ENABLE_Trace */

int parse_trace_mode(const char * mode, int * result) {
#if ENABLE_Trace
    int rval = 0;

    *result = 0;
    if (*mode == '\0') return 0;
    for(;;) {
        if (*mode >= '0' && *mode <= '9') {
            char * endptr;
            *result |= strtoul(mode, &endptr, 0);
            mode = endptr;
        }
        else {
            struct trace_mode *entry;
            const char * endptr = mode;
            while (*endptr != '\0' && *endptr != ',') endptr++;
            for (entry = trace_mode_table; entry->mode; entry++) {
                if (strncmp(mode, entry->name, endptr - mode) == 0 &&
                    entry->name[endptr - mode] == '\0')
                    break;
            }
            if (entry->mode == 0) rval = 1;
            *result |= entry->mode;
            mode = endptr;
        }
        if (*mode != ',') break;
        mode++;
    }
    if (*mode != '\0') return 1;
    return rval;
#else
    *result = 0;
    return 0;
#endif /* ENABLE_Trace */
}

int add_trace_mode(int mode, const char * name, const char * description) {
#if ENABLE_Trace
    int i;
    int busy = 0;

    for (i = 0; i < MAX_TRACE_MODES; i++) {
        if (trace_mode_table[i].mode == 0) {
            if (mode == 0) {
                /* Set mode to first unused bit. */
                mode = ~busy;
                if (mode == 0) break;
                mode &= ~(mode - 1);
            }
            trace_mode_table[i].mode = mode;
            trace_mode_table[i].name = name;
            trace_mode_table[i].description = description;
            return mode;
        }
        busy |= trace_mode_table[i].mode;
    }
#endif /* ENABLE_Trace */
    return 0;
}

void open_log_file(const char * log_name) {
#if ENABLE_Trace
    if (log_name == NULL) {
        log_file = NULL;
    }
    else if (strcmp(log_name, LOG_NAME_STDERR) == 0) {
        log_file = stderr;
    }
    else if ((log_file = fopen(log_name, "a")) == NULL) {
        fprintf(stderr, "TCF: error: cannot create log file %s\n", log_name);
        exit(1);
    }
#endif /* ENABLE_Trace */
}

void ini_trace(void) {
#if ENABLE_Trace
    if ((errno = pthread_mutex_init(&mutex, NULL)) != 0) {
        perror("pthread_mutex_init");
        exit(1);
    }
#endif /* ENABLE_Trace */
}
