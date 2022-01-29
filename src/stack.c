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

#include "stack.h"

Stack *initStack(Stack *s, size_t size)
{
    s->peek = NULL;
    s->size = 0;
    s->maxSize = size;
    return s;
}

inline void destroyStack(Stack *s)
{
    s = NULL;
}

ins32_t *pop(Stack *s)
{
    if (s->size == 0)
    {
        return NULL;
    }
    Node *res = s->peek;
    Node *prev = getPrev(s->peek);

    setPrev(s->peek, NULL);
    setNext(prev, NULL);
    s->size -= 1;
    return &(res->data);
}

int push(Stack *s, ins32_t *data)
{
    Node *n = createNode(*data);

    if (s->size == 0)
    {
        s->peek = n;
    }
    else if (s->size + 1 == s->maxSize)
    {
        return -1;
    }
    else
    {
        setNext(s->peek, n);
        setPrev(n, s->peek);
        s->peek = n;
    }

    s->size += 1;
    return s->size;
}

inline Node *peek(Stack *s)
{
    return s->peek;
}

inline size_t size(Stack *s)
{
    return s->size;
}

inline size_t maxSize(Stack *s)
{
    return s->maxSize;
}

inline uint8_t isEmpty(Stack *s)
{
    return s->size == 0;
}