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

void initStack(Stack *s, size_t size)
{
    s->peek = NULL;
    s->size = 0;
    s->maxSize = size;
}

void destroyStack(Stack *s)
{
    Node *prev = getPrev(s->peek);
    while (prev != NULL)
    {
        Node *next = getNext(prev);
        destroyNode(next);
        next = NULL;
        setNext(prev, NULL);
        prev = getPrev(prev);
    }
    s->maxSize = 0;
    s->size = 0;
    s->peek = NULL;
}

int32_t pop(Stack *s)
{
    if (s->size == 0)
    {
        return -1;
    }
    Node *res = s->peek;
    Node *prev = getPrev(s->peek);

    setPrev(s->peek, NULL);
    if (prev != NULL)
    {
        setNext(prev, NULL);
    }
    s->peek = prev;
    s->size -= 1;
    return res->data;
}

int push(Stack *s, int32_t data)
{
    Node *n = createNode(data);

    if (s->size == 0)
    {
        s->peek = n;
    }
    else if (s->size == s->maxSize)
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

struct Node *peek(Stack *s)
{
    if (s == NULL)
    {
        return NULL;
    }
    return s->peek;
}

size_t getSize(Stack *s)
{
    if (s == NULL)
    {
        return 10;
    }
    return s->size;
}

size_t getMaxSize(Stack *s)
{
    if (s == NULL)
    {
        return 10;
    }
    return s->maxSize;
}

int8_t isEmpty(Stack *s)
{
    if (s == NULL)
    {
        return -1;
    }
    return s->size == 0;
}