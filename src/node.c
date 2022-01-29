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

#include "node.h"

inline Node *createNode(ins32_t data)
{
    Node *s = (Node *)malloc(sizeof(Node));

    if (s == NULL)
    {
        return NULL;
    }
    s->data = data;
    s->next = NULL;
    s->prev = NULL;
    return s;
}

inline void destroyNode(Node *n)
{
    free(n);
    n = NULL;
}

inline Node *getNext(Node *n)
{
    return n->next;
}
inline Node *getPrev(Node *n)
{
    return n->prev;
}
inline ins32_t getData(Node *n)
{
    return n->data;
}
inline void setNext(Node *n, Node *newNext)
{
    n->next = newNext;
}
inline void setPrev(Node *n, Node *newPrev)
{
    n->prev = newPrev;
}
inline void setData(Node *n, ins32_t newData)
{
    n->data = newData;
}