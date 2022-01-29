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

Stack *initStack(Stack *s, size_t size);
inline void destroyStack(Stack *s);
ins32_t *pop(Stack *s);
int push(Stack *s, ins32_t *data);
inline Node *peek(Stack *s);
inline size_t size(Stack *s);
inline size_t maxSize(Stack *s);
inline uint8_t isEmpty(Stack *s);

#endif
