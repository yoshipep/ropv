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

Node *createNode(int32_t data)
{
    Node *s = (Node *)malloc(sizeof(struct Node));

    if (s == NULL)
    {
        return NULL;
    }
    s->data = data;
    s->next = NULL;
    s->prev = NULL;
    return s;
}

void destroyNode(struct Node *node)
{
    if (node == NULL)
    {
        return;
    }
    free(node);
}

Node *getNext(struct Node *n)
{
    if (n == NULL)
    {
        return NULL;
    }
    return n->next;
}

Node *getPrev(struct Node *n)
{
    if (n == NULL)
    {
        return NULL;
    }
    return n->prev;
}

int32_t getData(struct Node *n)
{
    if (n == NULL)
    {
        return -1;
    }
    return n->data;
}

void setNext(struct Node *n, struct Node *newNext)
{
    n->next = newNext;
}

void setPrev(struct Node *n, struct Node *newPrev)
{
    n->prev = newPrev;
}

void setData(struct Node *n, int32_t newData)
{
    n->data = newData;
}