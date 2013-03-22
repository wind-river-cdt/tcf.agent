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

#ifndef D_profiler
#define D_profiler

#include <tcf/config.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/protocol.h>

/*
 * Parameters to a profiler.
 */
typedef struct ProfilerParams {
    unsigned frame_cnt;
    unsigned max_smaples;
} ProfilerParams;

/*
 * Profiler class.
 */
typedef struct ProfilerClass {
    void * (*configure)(void * /* profiler */, Context * /* ctx */, ProfilerParams * /* params */);
    void (*read)(void * /* profiler */, OutputStream * /* out */);
    void (*dispose)(void * /* profiler */);
} ProfilerClass;

extern void add_profiler(Context * ctx, ProfilerClass * cls);

extern void ini_profiler_service(Protocol * proto);

#endif /* D_profiler */
