/*******************************************************************************
 * Copyright (c) 2007, 2010 Wind River Systems, Inc. and others.
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
 * Local memory heap manager.
 */

#include <tcf/config.h>
#include <assert.h>
#include <string.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/events.h>
#include <tcf/framework/myalloc.h>

#define TMP_POOL_SIZE (0x400 * MEM_USAGE_FACTOR)

typedef struct TmpBuffer TmpBuffer;

struct TmpBuffer {
    TmpBuffer * next;
    char buf[1];
};

static char tmp_pool[TMP_POOL_SIZE];
static int tmp_pool_pos = 0;
static TmpBuffer * tmp_alloc_list = NULL;
static int tmp_gc_posted = 0;

static void tmp_gc(void * args) {
    tmp_gc_posted = 0;
    while (tmp_alloc_list != NULL) {
        TmpBuffer * buf = tmp_alloc_list;
        tmp_alloc_list = buf->next;
        loc_free(buf);
    }
    tmp_pool_pos = 0;
}

void * tmp_alloc(size_t size) {
    void * p = NULL;
    assert(is_dispatch_thread());
    if (!tmp_gc_posted) {
        post_event(tmp_gc, NULL);
        tmp_gc_posted = 1;
    }
    if (tmp_pool_pos + size <= TMP_POOL_SIZE) {
        p = tmp_pool + tmp_pool_pos;
        tmp_pool_pos += size;
    }
    else {
        TmpBuffer * s = (TmpBuffer *)loc_alloc(sizeof(TmpBuffer) + size - 1);
        s->next = tmp_alloc_list;
        tmp_alloc_list = s;
        p = s->buf;
    }
    return p;
}

void * tmp_alloc_zero(size_t size) {
    void * p = tmp_alloc(size);
    memset(p, 0, size);
    return p;
}

void * loc_alloc(size_t size) {
    void * p;

    if (size == 0) {
        size = 1;
    }
    if ((p = malloc(size)) == NULL) {
        perror("malloc");
        exit(1);
    }
    trace(LOG_ALLOC, "loc_alloc(%u) = %#lx", (unsigned)size, p);
    return p;
}

void * loc_alloc_zero(size_t size) {
    void * p;

    if (size == 0) {
        size = 1;
    }
    if ((p = malloc(size)) == NULL) {
        perror("malloc");
        exit(1);
    }
    memset(p, 0, size);
    trace(LOG_ALLOC, "loc_alloc_zero(%u) = %#lx", (unsigned)size, p);
    return p;
}

void * loc_realloc(void * ptr, size_t size) {
    void * p;

    if (size == 0) {
        size = 1;
    }
    if ((p = realloc(ptr, size)) == NULL) {
        perror("realloc");
        exit(1);
    }
    trace(LOG_ALLOC, "loc_realloc(%#lx, %u) = %#lx", ptr, (unsigned)size, p);
    return p;
}

void loc_free(const void * p) {
    trace(LOG_ALLOC, "loc_free %#lx", p);
    free((void *)p);
}


/*
 * strdup() with end-of-memory checking.
 */
char * loc_strdup(const char * s) {
    char * rval = (char *)loc_alloc(strlen(s) + 1);
    strcpy(rval, s);
    return rval;
}


/*
 * strdup2() with concatenation and  end-of-memory checking.
 */
char * loc_strdup2(const char * s1, const char * s2) {
    char * rval = (char *)loc_alloc(strlen(s1) + strlen(s2) + 1);
    strcpy(rval, s1);
    strcat(rval, s2);
    return rval;
}


/*
 * strndup() with end-of-memory checking.
 */
char * loc_strndup(const char * s, size_t len) {
    char * rval = (char *)loc_alloc(len + 1);
    strncpy(rval, s, len);
    rval[len] = '\0';
    return rval;
}
