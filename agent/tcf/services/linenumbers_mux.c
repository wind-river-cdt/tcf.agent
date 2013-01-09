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
 * TCF service line Numbers - ELF version.
 *
 * The service associates locations in the source files with the corresponding
 * machine instruction addresses in the executable object.
 */

#include <tcf/config.h>

#if SERVICE_LineNumbers && !ENABLE_LineNumbersProxy && ENABLE_LineNumbersMux

#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <tcf/framework/myalloc.h>
#include <tcf/services/linenumbers.h>
#include <tcf/services/linenumbers_mux.h>

static LineNumbersReader ** readers = NULL;
static unsigned reader_count = 0;
static unsigned max_reader_count = 0;

#if ENABLE_ELF
extern void elf_ini_line_numbers_lib(void);
#endif
#if defined(_WIN32)
extern void win32_ini_line_numbers_lib(void);
#endif

int line_to_address(Context * ctx, char * file_name, int line, int column,
                    LineNumbersCallBack * client, void * args) {
    unsigned i;
    for (i = 0; i < reader_count; i++) {
        if (readers[i]->line_to_address(ctx, file_name, line, column, client, args) != 0) {
            return -1;
        }
    }
    return 0;
}

int address_to_line(Context * ctx, ContextAddress addr0, ContextAddress addr1,
        LineNumbersCallBack * client, void * args) {
    unsigned i;
    for (i = 0; i < reader_count; i++) {
        if (readers[i]->address_to_line(ctx, addr0, addr1, client, args) != 0) {
            return -1;
        }
    }
    return 0;
}

int add_line_numbers_reader(LineNumbersReader * reader) {
    if (reader_count >= max_reader_count) {
        max_reader_count += 2;
        readers = (LineNumbersReader **)loc_realloc(readers, max_reader_count * sizeof(reader));
    }
    readers[reader_count] = reader;
    reader->reader_index = reader_count;
    reader_count++;
    return 0;
}

void ini_line_numbers_lib(void) {
#if ENABLE_ELF
    elf_reader_ini_line_numbers_lib();
#endif
#if ENABLE_PE
    win32_reader_ini_line_numbers_lib();
#endif
}

#endif /* SERVICE_LineNumbers && !ENABLE_LineNumbersProxy && ENABLE_ELF */
