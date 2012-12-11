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
 * Local memory heap manager.
 */

#include <tcf/config.h>
#include <assert.h>
#include <string.h>
#include <tcf/framework/link.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/events.h>
#include <tcf/framework/myalloc.h>

#define ALIGNMENT (sizeof(size_t *))

#if !defined(ENABLE_FastMemAlloc)
#  define ENABLE_FastMemAlloc 1
#endif

#if !defined(USE_libc_malloc)
#  define USE_libc_malloc 1
#endif

#if ENABLE_FastMemAlloc
#define POOL_SIZE (0xfff0 * MEM_USAGE_FACTOR)
static char * tmp_pool = NULL;
static size_t tmp_pool_pos = 0;
static size_t tmp_pool_max = 0;
static size_t tmp_pool_avr = 0;
#endif

static LINK tmp_alloc_list = TCF_LIST_INIT(tmp_alloc_list);
static size_t tmp_alloc_size = 0;
static int tmp_gc_posted = 0;

static void gc_event(void * args) {
    tmp_gc_posted = 0;
    tmp_gc();
}

void tmp_gc(void) {
#if ENABLE_FastMemAlloc
    if (tmp_pool_pos + tmp_alloc_size >= tmp_pool_avr) {
        tmp_pool_avr = tmp_pool_pos + tmp_alloc_size;
    }
    else if (tmp_pool_avr > POOL_SIZE / 0x10) {
        tmp_pool_avr -= POOL_SIZE / 0x10000;
    }
    if (tmp_pool_max < tmp_pool_avr && tmp_pool_max < POOL_SIZE) {
        if (tmp_pool_max < POOL_SIZE / 0x10) tmp_pool_max = POOL_SIZE / 0x10;
        while (tmp_pool_max < tmp_pool_avr) tmp_pool_max *= 2;
        if (tmp_pool_max > POOL_SIZE) tmp_pool_max = POOL_SIZE;
        tmp_pool = (char *)loc_realloc(tmp_pool, tmp_pool_max);
    }
    else if (tmp_pool_avr < tmp_pool_max / 4 && tmp_pool_max > POOL_SIZE / 0x10) {
        tmp_pool_max /= 2;
        tmp_pool = (char *)loc_realloc(tmp_pool, tmp_pool_max);
    }
    tmp_pool_pos = 0;
#endif
    while (!list_is_empty(&tmp_alloc_list)) {
        LINK * l = tmp_alloc_list.next;
        list_remove(l);
        loc_free(l);
    }
    tmp_alloc_size = 0;
}

void * tmp_alloc(size_t size) {
    void * p;
    assert(is_dispatch_thread());
    if (!tmp_gc_posted) {
        post_event(gc_event, NULL);
        tmp_gc_posted = 1;
    }
#if ENABLE_FastMemAlloc
    if (tmp_pool_max == 0) {
        assert(tmp_pool_pos == 0);
        tmp_pool_max = POOL_SIZE / 0x10;
        tmp_pool = (char *)loc_alloc(tmp_pool_max);
    }
    if (tmp_pool_pos + size + ALIGNMENT + sizeof(size_t *) <= tmp_pool_max) {
        tmp_pool_pos += sizeof(size_t *);
        tmp_pool_pos = (tmp_pool_pos + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
        p = tmp_pool + tmp_pool_pos;
        *((size_t *)p - 1) = size;
        tmp_pool_pos += size;
        return p;
    }
#endif
    {
        LINK * l = (LINK *)loc_alloc(sizeof(LINK) + size);
        list_add_last(l, &tmp_alloc_list);
        tmp_alloc_size += size + ALIGNMENT + sizeof(size_t *);
        p = l + 1;
    }
    return p;
}

void * tmp_alloc_zero(size_t size) {
    return memset(tmp_alloc(size), 0, size);
}

void * tmp_realloc(void * ptr, size_t size) {
    if (ptr == NULL) return tmp_alloc(size);
    assert(is_dispatch_thread());
    assert(tmp_gc_posted);
#if ENABLE_FastMemAlloc
    if ((char *)ptr >= tmp_pool && (char *)ptr <= tmp_pool + tmp_pool_max) {
        size_t m = *((size_t *)ptr - 1);
        if (m < size) {
            size_t pos = tmp_pool_pos - m;
            if (ptr == tmp_pool + pos && pos + size <= tmp_pool_max) {
                tmp_pool_pos = pos + size;
                *((size_t *)ptr - 1) = size;
            }
            else {
                void * p = tmp_alloc(size);
                if (m > size) m = size;
                ptr = memcpy(p, ptr, m);
            }
        }
        return ptr;
    }
#endif
    {
        LINK * l = (LINK *)ptr - 1;
        list_remove(l);
        l = (LINK *)loc_realloc(l, sizeof(LINK) + size);
        list_add_last(l, &tmp_alloc_list);
        ptr = l + 1;
    }
    return ptr;
}

char * tmp_strdup(const char * s) {
    char * rval = (char *)tmp_alloc(strlen(s) + 1);
    strcpy(rval, s);
    return rval;
}

char * tmp_strdup2(const char * s1, const char * s2) {
    size_t l1 = strlen(s1);
    size_t l2 = strlen(s2);
    char * rval = (char *)tmp_alloc(l1 + l2 + 1);
    memcpy(rval, s1, l1);
    memcpy(rval + l1, s2, l2 + 1);
    return rval;
}

#if USE_libc_malloc

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

    if (size == 0) size = 1;
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

    if (size == 0) size = 1;
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

#endif /* USE_libc_malloc */

/* strdup() with end-of-memory checking. */
char * loc_strdup(const char * s) {
    char * rval = (char *)loc_alloc(strlen(s) + 1);
    strcpy(rval, s);
    return rval;
}

/* strdup2() with concatenation and  end-of-memory checking. */
char * loc_strdup2(const char * s1, const char * s2) {
    size_t l1 = strlen(s1);
    size_t l2 = strlen(s2);
    char * rval = (char *)loc_alloc(l1 + l2 + 1);
    memcpy(rval, s1, l1);
    memcpy(rval + l1, s2, l2 + 1);
    return rval;
}

/* strndup() with end-of-memory checking. */
char * loc_strndup(const char * s, size_t len) {
    char * rval = (char *)loc_alloc(len + 1);
    strncpy(rval, s, len);
    rval[len] = '\0';
    return rval;
}
