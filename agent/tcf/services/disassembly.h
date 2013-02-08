/*******************************************************************************
 * Copyright (c) 2013 Xilinx, Inc. and others.
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
 *     Xilinx - initial API and implementation
 *******************************************************************************/

#ifndef D_disassembly
#define D_disassembly

#include <tcf/config.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/protocol.h>

typedef struct {
    const char * text;
    ContextAddress size;
    int incomplete;
} DisassemblyResult;

typedef DisassemblyResult * Disassembler(uint8_t * /* code */, ContextAddress /* addr */, ContextAddress /* size */);

extern void add_disassembler(Context * ctx, const char * isa, Disassembler disassembler);

extern void ini_disassembly_service(Protocol * proto);

#endif /* D_disassembly */
