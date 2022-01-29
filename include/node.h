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
    ins32_t data;
    struct Node *next;
    struct Node *prev;
} Node;

inline Node *createNode(ins32_t data);
inline void destroyNode(Node *n);
inline Node *getNext(Node *n);
inline Node *getPrev(Node *n);
inline ins32_t getData(Node *n);
inline void setNext(Node *n, Node *newNext);
inline void setPrev(Node *n, Node *newPrev);
inline void setData(Node *n, ins32_t newData);

#endif