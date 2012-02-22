/*******************************************************************************
 * Copyright (c) 2007, 2011 Wind River Systems, Inc. and others.
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
#define POOL_SIZE (0x100000 * MEM_USAGE_FACTOR)

static char * tmp_pool = NULL;
static size_t tmp_pool_pos = 0;
static size_t tmp_pool_max = 0;
static size_t tmp_pool_avr = 0;
static size_t tmp_alloc_size = 0;
static LINK tmp_alloc_list = TCF_LIST_INIT(tmp_alloc_list);
static int tmp_gc_posted = 0;

static void gc_event(void * args) {
    tmp_gc_posted = 0;
    tmp_gc();
}

void tmp_gc(void) {
    if (!list_is_empty(&tmp_alloc_list)) {
        if (tmp_pool_max < POOL_SIZE) {
            tmp_pool_max += tmp_pool_max > tmp_alloc_size ? tmp_pool_max : tmp_alloc_size;
            if (tmp_pool_max > POOL_SIZE) tmp_pool_max = POOL_SIZE;
            tmp_pool = (char *)loc_realloc(tmp_pool, tmp_pool_max);
        }
        while (!list_is_empty(&tmp_alloc_list)) {
            LINK * l = tmp_alloc_list.next;
            list_remove(l);
            loc_free(l);
        }
    }
    if (tmp_pool_pos + tmp_alloc_size >= tmp_pool_avr) {
        tmp_pool_avr = tmp_pool_pos + tmp_alloc_size;
    }
    else if (tmp_pool_avr > POOL_SIZE / 100) {
        tmp_pool_avr -= POOL_SIZE / 100;
    }
    if (tmp_pool_avr < tmp_pool_max / 4) {
        tmp_pool_max /= 2;
        tmp_pool = (char *)loc_realloc(tmp_pool, tmp_pool_max);
    }
    tmp_pool_pos = 0;
    tmp_alloc_size = 0;
}

void * tmp_alloc(size_t size) {
    void * p = NULL;
    assert(is_dispatch_thread());
    if (!tmp_gc_posted) {
        post_event(gc_event, NULL);
        tmp_gc_posted = 1;
    }
    if (tmp_pool_pos + size + ALIGNMENT + sizeof(size_t *) <= tmp_pool_max) {
        tmp_pool_pos += sizeof(size_t *);
        tmp_pool_pos = (tmp_pool_pos + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
        p = tmp_pool + tmp_pool_pos;
        *((size_t *)p - 1) = size;
        tmp_pool_pos += size;
    }
    else {
        LINK * l = (LINK *)loc_alloc(sizeof(LINK) + size);
        list_add_last(l, &tmp_alloc_list);
        tmp_alloc_size += size;
        p = l + 1;
    }
    return p;
}

void * tmp_alloc_zero(size_t size) {
    return memset(tmp_alloc(size), 0, size);
}

void * tmp_realloc(void * ptr, size_t size) {
    if (ptr == NULL) return tmp_alloc(size);
    if ((char *)ptr >= tmp_pool && (char *)ptr <= tmp_pool + tmp_pool_max) {
        size_t m = *((size_t *)ptr - 1);
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
    else {
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
    char * rval = (char *)tmp_alloc(strlen(s1) + strlen(s2) + 1);
    strcpy(rval, s1);
    strcat(rval, s2);
    return rval;
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
