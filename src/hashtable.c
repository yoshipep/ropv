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

#include "hashtable.h"

#define LOAD_FACTOR 0.75f

static size_t hashIndex(const unsigned char *key, size_t capacity);

static uint16_t hash(const unsigned char *str);

static float factorCarga(struct hastable_t *table);

static int *recuperar(struct _entry_t *entry, const unsigned char *key);

static void rehashing(struct hastable_t *table);

static unsigned char **getKeys(struct hastable_t *table);

struct hastable_t *create(uint16_t initialCapacity)
{
    struct hastable_t *table = (hastable_t *)malloc(sizeof(struct hastable_t));
    table->entries = (struct _entry_t *)calloc(initialCapacity, sizeof(_entry_t));
    table->size = 0;
    table->capacity = initialCapacity;
    return table;
}

static size_t hashIndex(const unsigned char *key, size_t capacity)
{
    uint16_t index = hash(key) % capacity;
    if (index < 0)
    {
        index += capacity;
    }
    return index;
}

/*
 * See: https://stackoverflow.com/questions/40303333/how-to-replicate-java-hashcode-in-c-language
 */
static uint16_t hash(const unsigned char *str)
{
    size_t i;
    size_t length = strlen(str);
    uint16_t hash = 0;

    for (i = 0; i < length; i++)
    {
        hash = 31 * hash + str[i];
    }

    return hash;
}

static float factorCarga(struct hastable_t *table)
{
    return (float)table->size / table->capacity;
}

int *insert(struct hastable_t *table, int *data, const unsigned char *key)
{
    if ((table->capacity == table->size) || (factorCarga(table) > LOAD_FACTOR))
    {
        rehashing(table);
        return NULL;
    }

    int *res;
    uint16_t pos;
    struct _entry_t *entries, *last;

    pos = hashIndex(key, table->capacity);
    entries = &table->entries[pos];
    last = NULL;

    while ((NULL != entries) && (NULL != entries->key) && (0 != strcmp(entries->key, key)))
    {
        last = entries;
        entries = entries->next;
    }

    if (NULL == entries)
    {
        entries = calloc(1, sizeof(struct _entry_t));
        if (NULL != last)
        {
            last->next = entries;
        }

        entries->key = key;
        entries->data = data;
        if (factorCarga(table) > LOAD_FACTOR)
        {
            rehashing(table);
        }
    }
    else
    {
        res = entries->data;
        entries->key = key;
        entries->data = data;
    }
    table->size++;
    return res;
}

int *delete (struct hastable_t *table, const unsigned char *key)
{
    if (0 == table->size)
    {
        return NULL;
    }

    int *res;
    uint16_t pos;
    struct _entry_t *entries, *last;

    pos = hashIndex(key, table->capacity);
    entries = &table->entries[pos];
    last = NULL;

    while ((NULL != entries) && (NULL != entries->key) && (0 != strcmp(entries->key, key)))
    {
        last = entries;
        entries = entries->next;
    }

    if (NULL == entries)
    {
        return NULL;
    }

    else
    {
        table->size--;
        res = entries->data;
        if ((NULL == last) && (NULL == entries->next))
        {
            memset(entries, 0x0, sizeof(_entry_t));
        }

        else if ((NULL != entries->next))
        {
            struct _entry_t *aux = entries->next;
            memcpy(entries, entries->next, sizeof(_entry_t));
            aux->next = NULL;
            free(aux);
            aux = NULL;
        }

        else
        {
            last->next = entries->next;
            free(entries);
            entries = NULL;
        }

        return res;
    }
}

static int *recuperar(struct _entry_t *entry, const unsigned char *key)
{
    struct _entry_t *aux = entry;

    while ((NULL != aux) && (NULL != aux->key) && (0 != strcmp(aux->key, key)))
    {
        aux = aux->next;
    }

    if (NULL == aux)
    {
        return NULL;
    }

    else
    {
        return aux->data;
    }
}

static void rehashing(struct hastable_t *table)
{
    if (factorCarga(table) > LOAD_FACTOR)
    {
        size_t i;
        struct hastable_t *aux = table;
        struct hastable_t *newTable = create(table->capacity * 2);

        for (i = 0; i < table->size; i++)
        {
            struct _entry_t *entries = &table->entries[i];
            while (NULL != entries)
            {
                if (NULL != entries->key)
                {
                    insert(newTable, entries->data, entries->key);
                }
                entries = entries->next;
            }
        }
        table = newTable;
        free(aux);
    }
}

bool find(struct hastable_t *table, const unsigned char *key)
{
    size_t pos = hashIndex(key, table->capacity);
    return !(NULL == recuperar(&table->entries[pos], key));
}

static unsigned char **getKeys(struct hastable_t *table)
{
    size_t i;
    unsigned char **keys = (unsigned char **)malloc(table->size * sizeof(unsigned char *) + 1);
    size_t j = 0;

    for (i = 0; i < table->capacity; i++)
    {
        struct _entry_t *entry = &table->entries[i];
        while (NULL != entry)
        {
            if (NULL != entry->key)
            {
                keys[j++] = (unsigned char *)strdup(entry->key);
            }
            entry = entry->next;
        }
    }
    keys[j] = 0x0;
    return keys;
}

void printContent(struct hastable_t *table)
{
    if (NULL == table)
    {
        return;
    }
    int *valor;
    size_t pos;
    size_t i = 0;
    unsigned char **keys = getKeys(table);

    while (keys[i])
    {
        pos = hashIndex(keys[i], table->capacity);
        valor = recuperar(&table->entries[pos], keys[i]);
        printf("C: %s\tV: %d\n", keys[i], *valor);
        i++;
    }
}