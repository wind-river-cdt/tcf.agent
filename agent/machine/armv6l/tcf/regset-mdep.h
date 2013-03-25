/*******************************************************************************
 * Copyright (c) 2013 Stanislav Yakovlev and others.
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
 *     Stanislav Yakovlev - initial API and implementation
 * Emmanuel Touron (Wind River) - initial HW Breakpoint support
 *******************************************************************************/

/* offset to be applied to the PC after a software trap */
#define TRAP_OFFSET 0

#define MAX_HBP 1
typedef struct {
    uint32_t vr;
    uint32_t cr;
} user_hbpreg_struct;

struct user_hbpregs_struct {
    uint32_t bp_info;
    user_hbpreg_struct bp[MAX_HBP];
//    user_hbpreg_struct wp[MAX_HBP];
};

/* additional CPU registers */
#define MDEP_OtherRegisters struct user_hbpregs_struct
