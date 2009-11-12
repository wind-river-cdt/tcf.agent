/*******************************************************************************
 * Copyright (c) 2007, 2009 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * TCF service Line Numbers
 * The service associates locations in the source files with the corresponding
 * machine instruction addresses in the executable object.
 */

#ifndef D_linenumbers
#define D_linenumbers

#include "protocol.h"
#include "context.h"

typedef void LineToAddressCallBack(void *, ContextAddress);

extern int line_to_address(Context * ctx, char * file, int line, int column, LineToAddressCallBack *, void * args);

/*
 * Initialize Line Numbers service.
 */
extern void ini_line_numbers_service(Protocol *);


#endif /* D_linenumbers */
