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

#include "stack.h"

int main()
{
    Stack s, t;
    initStack(&s, 5);
    initStack(&t, 5);
    printf("Size of the stack: %ld\nMaximum size of the stack: %ld\nTop of the stack: %p\n", getSize(&s), getMaxSize(&s), peek(&s));
    printf("Popping from the stack with %ld elements: %d\n", getSize(&s), pop(&s));

    for (size_t i = 0; i < 6; i++)
    {
        if (push(&s, i) == -1)
        {
            printf("You are trying to push more elements than the maximum size\n");
        }
        push(&t, i);
        printf("Pushing element to the stack. Size of the stack: %ld\nTop of the stack: %p\n", getSize(&s), peek(&s));
    }

    for (size_t i = 0; i < 5; i++)
    {
        printf("Popping from the stack with %ld elements...\n", getSize(&s));
        printf("Popped element: %d\n", pop(&s));
    }

    printf("Values from the stack to be destroyed: S: %ld\tMS: %ld\tP: %p\n", getSize(&t), getMaxSize(&t), peek(&t));
    destroyStack(&t);
    printf("Values from the stack to be destroyed: S: %ld\tMS: %ld\tP: %p\n", getSize(&t), getMaxSize(&t), peek(&t));

    return 0;
}