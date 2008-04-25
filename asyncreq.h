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
 * Asynchronous system call request interface
 */

#ifndef D_asyncreq
#define D_asyncreq

#include "link.h"

enum {
    AsyncReqRead,                       /* File read */
    AsyncReqWrite,                      /* File write */
    AsyncReqRecv,                       /* Socket recv */
    AsyncReqSend,                       /* Socket send */
    AsyncReqRecvFrom,                   /* Socket recvfrom */
    AsyncReqSendTo,                     /* Socket sendto */
    AsyncReqAccept,                     /* Accept socket connections */
    AsyncReqConnect,                    /* Connect to socket */
    AsyncReqWaitpid                     /* Wait for process change */
};

typedef struct AsyncReqInfo AsyncReqInfo;
struct AsyncReqInfo {
    void (*done)(void *req);
    void *client_data;
    int type;
    union {
        struct {
            /* In */
            int fd;
            void *bufp;
            size_t bufsz;

            /* Out */
            size_t rval;
        } fio;
        struct {
            /* In */
            int sock;
            void *bufp;
            size_t bufsz;
            int flags;
            struct sockaddr *addr;
#if defined(_WRS_KERNEL)
            int addrlen;
#else       
            socklen_t addrlen;
#endif

            /* Out */
            size_t rval;
        } sio;
        struct {
            /* In */
            int sock;
            struct sockaddr *addr;
#if defined(_WRS_KERNEL)
            int addrlen;
#else       
            socklen_t addrlen;
#endif
            
            /* Out */
            int rval;
        } acc;
        struct {
            /* In */
            int sock;
            struct sockaddr *addr;
            socklen_t addrlen;

            /* Out */
            int rval;
        } con;
        struct {
            /* In */
            pid_t pid;
            int options;

            /* Out */
            int status;
            pid_t rval;
        } wpid;
    } u;
    int error;                  /* Readable by callback function */

    /* Private - the following members should only be used by the
     * asyncreq implementation */
    LINK reqlink;                       /* List of pending requests */
};

void async_req_post(AsyncReqInfo *req);

void ini_asyncreq(void);

#endif