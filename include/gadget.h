/*
 * Copyright (C) 2022 Josep Comes Sanchis
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _GADGET_H
#define _GADGET_H 1

#define MAX_LENGTH 30

#include <stdint.h>

#include "datatypes.h"
#include "node.h"

typedef struct gadget_t
{
    ins32_t *instructions[MAX_LENGTH];
    uint8_t length;
} gadget_t;

extern struct arguments args;

extern ins32_t *preliminary_gadget_list[100];

extern struct node_t *list;

struct node_t *spDuplicated;

void processGadgets(uint8_t lastElement, op_t lastOperation);

void printGadget(struct gadget_t *gadget);

#endif