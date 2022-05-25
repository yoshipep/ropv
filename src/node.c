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

struct node_t *create()
{
    struct node_t *list = (node_t *)calloc(1, sizeof(struct node_t));
    return list;
}

struct node_t *insert(struct node_t *list, struct gadget_t *data, const char *key)
{
    list->key = strdup(key);
    list->data = data;
    list->next = create();
    return list->next;
}

bool find(struct node_t *list, const char *key)
{
    struct node_t *head = list;
    while (NULL != head->data)
    {
        if (0 == strcmp(head->key, key))
        {
            return true;
        }
        head = head->next;
    }
    return false;
}

void printContent(struct node_t *list)
{
    struct node_t *head = list;
    while (NULL != head->data)
    {
        printGadget(head->data);
        head = head->next;
    }
}