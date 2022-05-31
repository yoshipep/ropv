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

#include "hashtable.h"

#define LOAD_FACTOR 0.75f

static size_t hashIndex(const char *key, size_t capacity);

static int16_t hash(const char *str);

static float factorCarga(struct hashtable_t *table);

static struct gadget_t *recuperar(struct _entry_t *entry, const char *key);

static struct hashtable_t *rehashing(struct hashtable_t *table);

static const char **getKeys(struct hashtable_t *table);

struct hashtable_t *create(uint16_t initialCapacity)
{
    struct hashtable_t *table = (hashtable_t *)malloc(sizeof(hashtable_t));
    table->entries = (struct _entry_t *)calloc(initialCapacity, sizeof(_entry_t));
    table->size = 0;
    table->capacity = initialCapacity;
    return table;
}

void destroy(struct hashtable_t *table)
{
    if (NULL == table)
    {
        return;
    }

    free(table->entries);
    table->entries = NULL;
    free(table);
    table = NULL;
}

struct gadget_t *insert(hashtable_t **table, struct gadget_t *data, const char *key)
{
    if ((NULL == table) || (NULL == *table) || (NULL == key) ||
        (0 == strlen(key)) || (NULL == data))
    {
        return NULL;
    }

    if (((*table)->capacity == (*table)->size) ||
        (factorCarga(*table) > LOAD_FACTOR))
    {
        hashtable_t *aux = rehashing(*table);
        *table = aux;
        return NULL;
    }

    struct gadget_t *res;
    uint16_t pos;
    struct _entry_t *entries, *last;

    pos = hashIndex(key, (*table)->capacity);
    entries = &(*table)->entries[pos];
    last = NULL;

    while ((NULL != entries) && (NULL != entries->key) &&
           (0 != strcmp(entries->key, key)))
    {
        last = entries;
        entries = entries->next;
    }

    if (NULL == entries)
    {
        entries = calloc(1, sizeof(_entry_t));
        if (NULL != last)
        {
            last->next = entries;
        }

        entries->key = key;
        entries->data = data;
        if (factorCarga(*table) > LOAD_FACTOR)
        {
            hashtable_t *aux = rehashing(*table);
            *table = aux;
        }
        (*table)->size++;
    }

    else
    {
        res = entries->data;
        entries->key = key;
        entries->data = data;
        if (NULL == last)
        {
            (*table)->size++;
        }
    }
    return res;
}

struct gadget_t *delete (struct hashtable_t *table, const char *key)
{
    if ((NULL == table) || (0 == table->size) || (NULL == key) ||
        (0 == strlen(key)))
    {
        return NULL;
    }

    struct gadget_t *res;
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

union result find(struct hashtable_t *table, const char *key)
{
    union result res;
    if ((NULL == table) || (NULL == key) || (0 == strlen(key)))
    {
        res.null = NULL;
        return res;
    }
    size_t pos = hashIndex(key, table->capacity);
    res.boolean = !(NULL == recuperar(&table->entries[pos], key));
    return res;
}

void printContent(struct hashtable_t *table)
{
    if (NULL == table)
    {
        return;
    }
    int *valor;
    size_t pos;
    size_t i = 0;
    const char **keys = getKeys(table);

    while (keys[i])
    {
        pos = hashIndex(keys[i], table->capacity);
        valor = recuperar(&table->entries[pos], keys[i]);
        printGadget(valor);
        i++;
    }
    free(keys);
    keys = NULL;
}

static size_t hashIndex(const char *key, size_t capacity)
{
    int16_t index = hash(key) % capacity;
    if (index < 0)
    {
        index += capacity;
    }
    return index;
}

/*
 * See: https://stackoverflow.com/questions/40303333/how-to-replicate-java-hashcode-in-c-language
 */
static int16_t hash(const char *str)
{
    size_t i;
    size_t length = strlen(str);
    int16_t hash = 0;

    for (i = 0; i < length; i++)
    {
        hash = 31 * hash + str[i];
    }

    return hash;
}

static float factorCarga(struct hashtable_t *table)
{
    return (float)table->size / table->capacity;
}

static struct gadget_t *recuperar(struct _entry_t *entry, const char *key)
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

static struct hashtable_t *rehashing(struct hashtable_t *table)
{
    size_t i;
    struct hashtable_t *newTable = create(table->capacity * 2);

    for (i = 0; i < table->size; i++)
    {
        struct _entry_t *entries = &table->entries[i];
        while (NULL != entries)
        {
            if (NULL != entries->key)
            {
                insert(&newTable, entries->data, entries->key);
            }
            entries = entries->next;
        }
    }
    destroy(table);
    return newTable;
}

static const char **getKeys(hashtable_t *table)
{
    size_t i;
    const char **keys = (const char **)calloc(table->size + 1, sizeof(const char *));
    size_t j = 0;

    for (i = 0; i < table->capacity; i++)
    {
        struct _entry_t *entry = &table->entries[i];
        while (NULL != entry)
        {
            if (NULL != entry->key)
            {
                keys[j++] = entry->key;
            }
            entry = entry->next;
        }
    }
    return keys;
}
