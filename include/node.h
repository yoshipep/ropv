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

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "gadget.h"

typedef struct node_t
{
    const char *key;
    struct gadget_t *data;
    struct node_t *next;
} node_t;

struct node_t *create();

struct node_t *insert(struct node_t *list, struct gadget_t *data, const char *key);

// struct node_t *remove(struct node_t *list, const char *key);

bool find(struct node_t *list, const char *key);

void printContent(struct node_t *list);

#endif