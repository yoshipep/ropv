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

#include <stdio.h>

#include "node.h"

int main()
{
    Node *s = createNode(32);
    Node *p = createNode(8);
    Node *t = createNode(24);
    printf("Value in the node: %d\nPrev node: %p\nNext node: %p\n", getData(s), getPrev(s), getNext(s));
    setData(s, 16);
    setNext(s, p);
    setPrev(s, t);
    printf("Value in the node: %d\nPrev node: %p\tPrev data: %d\nNext node: %p\tNext data: %d\n", getData(s), getPrev(s), getData(t), getNext(s), getData(p));
    setPrev(s, NULL);
    printf("New prev node: %p\n", getPrev(s));

    printf("Values from the node to be destroyed: V: %d\tP: %p\tN: %p\n", getData(s), getPrev(s), getNext(s));
    destroyNode(s);
    s = NULL;
    printf("Values from the destroyed node: V: %d\tP: %p\tN: %p\n", getData(s), getPrev(s), getNext(s));
    return 0;
}