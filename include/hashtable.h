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

#ifndef _HASHTABLE_H
#define _HASHTABLE_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct _entry_t
{
    const unsigned char *key;
    int *data;
    struct _entry_t *next;
} _entry_t;

typedef struct hashtable_t
{
    struct _entry_t *entries;
    size_t size;
    size_t capacity;
} hashtable_t;

struct hashtable_t *create(uint16_t initialCapacity);

void destroy(struct hashtable_t *table);

int *insert(struct hashtable_t **table, int *data, const unsigned char *key);

int *delete (struct hashtable_t *table, const unsigned char *key);

bool find(struct hashtable_t *table, const unsigned char *key);

void printContent(struct hashtable_t *table);

#endif