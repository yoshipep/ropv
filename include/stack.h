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

#ifndef _STACK_H
#define _STACK_H 1

#include <stdint.h>
#include <stdlib.h>

#include "datatypes.h"
#include "node.h"

typedef struct Stack
{
    size_t size;
    struct Node *peek;
    size_t maxSize;

} Stack;

void initStack(Stack *s, size_t size);
void destroyStack(Stack *s);
int32_t pop(Stack *s);
int push(Stack *s, int32_t data);
struct Node *peek(Stack *s);
size_t getSize(Stack *s);
size_t getMaxSize(Stack *s);
int8_t isEmpty(Stack *s);

#endif
