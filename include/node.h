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

#ifndef _NODE_H
#define _NODE_H 1

#include <stdlib.h>

#include "datatypes.h"

typedef struct Node
{
    int32_t data;
    struct Node *next;
    struct Node *prev;
} Node;

Node *createNode(int32_t data);
void destroyNode(struct Node *node);
Node *getNext(struct Node *n);
Node *getPrev(struct Node *n);
int32_t getData(struct Node *n);
void setNext(struct Node *n, struct Node *newNext);
void setPrev(struct Node *n, struct Node *newPrev);
void setData(struct Node *n, int32_t newData);

#endif