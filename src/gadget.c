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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "datatypes.h"
#include "gadget.h"

#define MAX_LENGTH_NO_RET 6

static struct node_t *last = NULL;

static struct node_t *lastSp = NULL;

static char *prettifyString(char *src);

static struct gadget_t *retFilter(uint16_t lastElement);

static struct gadget_t *jopFilter(struct gadget_t *gadget);

static struct gadget_t *noRetFilter(uint16_t lastElement);

static char *generateKey(struct gadget_t *gadget);

static char *updateKey(char *key);

static bool checkValidity(struct ins32_t *instruction);

static bool messSp(struct ins32_t *instruction);

static __attribute__((always_inline)) inline bool isLastInstruction(struct ins32_t *instruction);

static inline bool isLastInstruction(struct ins32_t *instruction)
{
    return (LOAD == instruction->operation) &&
           (0 == strcmp(instruction->regDest, "ra"));
}

static bool checkValidity(struct ins32_t *instruction)
{
    return (CMP != instruction->operation) && (JMP != instruction->operation) &&
           (BRK != instruction->operation) && (RET != instruction->operation) &&
           (CALL != instruction->operation) &&
           (SYSCALL != instruction->operation) &&
           (UNSUPORTED != instruction->operation) &&
           (ATOMIC != instruction->operation) && (IO != instruction->operation) &&
           !strstr(instruction->disassembled, "auipc") && !messSp(instruction);
}

static bool messSp(struct ins32_t *instruction)
{
    return ((ADD == instruction->operation) && instruction->useImmediate &&
            (instruction->immediate < 0) &&
            strstr(instruction->disassembled, "addi\tsp")) ||
           ((SUB == instruction->operation) &&
            strstr(instruction->disassembled, "sub\tsp"));
}

static struct gadget_t *retFilter(uint16_t lastElement)
{
    uint16_t current;
    struct gadget_t *gadget = (gadget_t *)calloc(1, sizeof(struct gadget_t));

    gadget->instructions[0] = preliminary_gadget_list[lastElement];
    gadget->length = 1;
    current = 0 == lastElement ? 99 : lastElement - gadget->length;
    while (gadget->length < MAX_LENGTH && checkValidity(preliminary_gadget_list[current]) &&
           !isLastInstruction(preliminary_gadget_list[current]))
    {
        gadget->instructions[gadget->length] = preliminary_gadget_list[current];
        gadget->length++;
        if (0 == current)
        {
            current = 99;
        }

        else
        {
            current--;
            if (0 == current)
                current = 99;
        }
    }

    if (isLastInstruction(preliminary_gadget_list[current]))
    {
        gadget->instructions[gadget->length] = preliminary_gadget_list[current];
        gadget->length++;
        return gadget;
    }
    free(gadget);
    return NULL;
}

static struct gadget_t *jopFilter(struct gadget_t *gadget)
{
    int8_t i;
    char *refRegister;
    uint8_t nCoindicendes = 0;
    refRegister = gadget->instructions[0]->regDest;

    for (i = gadget->length - 1; i >= 1; i--)
    {
        if (0 == strcmp(refRegister, gadget->instructions[i]->regDest))
        {
            nCoindicendes++;
        }
    }

    if (nCoindicendes >= (gadget->length / 2))
    {
        free(gadget);
        return NULL;
    }
    return gadget;
}

static struct gadget_t *noRetFilter(uint16_t lastElement)
{
    uint16_t current;
    struct gadget_t *gadget = (gadget_t *)calloc(1, sizeof(struct gadget_t));

    gadget->instructions[0] = preliminary_gadget_list[lastElement];
    gadget->length = 1;
    current = 0 == lastElement ? 99 : lastElement - gadget->length;
    while (gadget->length < MAX_LENGTH_NO_RET &&
           checkValidity(preliminary_gadget_list[current]))
    {
        gadget->instructions[gadget->length] = preliminary_gadget_list[current];
        gadget->length++;
        if (0 == current)
        {
            current = 99;
        }

        else
        {
            current--;
            if (0 == current)
                current = 99;
        }
    }
    return gadget;
}

void processGadgets(uint8_t lastElement, op_t lastOperation)
{
    char *key, *tmp, *newKey;
    uint8_t index;
    struct node_t *found;
    struct gadget_t *gadget;

    switch (lastOperation)
    {
    case RET:
        gadget = retFilter(lastElement);
        break;
    case SYSCALL:
        gadget = noRetFilter(lastElement);
        break;
    case JMP:
        gadget = noRetFilter(lastElement);
        gadget = jopFilter(gadget);
        break;
    default:
        break;
    }

    if ((NULL != gadget) || (NULL != gadget && gadget->length > 0))
    {
        key = generateKey(gadget);

        if (NULL == last)
        {
            last = list;
        }

        for (index = 0; index < gadget->length; index++)
        {
            if ((ADD == gadget->instructions[index]->operation) &&
                (gadget->instructions[index]->useImmediate) &&
                (0 == strcmp(gadget->instructions[index]->regDest, "sp")))
            {
                break;
            }
        }

        if ((gadget->length >= 2) && (index < gadget->length))
        {

            if (NULL == lastSp)
            {
                lastSp = spDuplicated;
            }

            newKey = updateKey(key);
            found = find(spDuplicated, newKey);

            if (NULL == found)
            {
                lastSp = insert(lastSp, gadget, newKey);
                last = insert(last, gadget, key);
            }

            else
            {
                if (found->data->instructions[index]->immediate > gadget->instructions[index]->immediate)
                {
                    tmp = generateKey(found->data);
                    update(found, gadget, newKey);
                    delete (list, tmp);
                    free(tmp);
                    tmp = NULL;
                }
            }
            free(key);
            free(newKey);
            key = NULL;
            newKey = NULL;
        }
        else
        {
            if (NULL == find(list, key))
            {
                last = insert(last, gadget, key);
            }
        }
    }
}

// Generates a key where all the instructions have no separation
static char *generateKey(struct gadget_t *gadget)
{
    int8_t i;
    size_t length;
    char *prettified;
    uint8_t index = 0;
    char *buf = (char *)calloc(700, sizeof(char));

    for (i = gadget->length - 1; i >= 0; i--)
    {
        prettified = prettifyString(gadget->instructions[i]->disassembled);
        length = strlen(prettified);
        strncpy(&buf[index], prettified, length);
        index += length;
        free(prettified);
    }
    return buf;
}

// Prettifies the string before gets printed
static char *prettifyString(char *src)
{
    char last, *res, buf[50];
    uint8_t length;
    uint8_t i = 0;

    while (*src)
    {
        if (0x20 == *src && 0x20 == last)
        {
            last = *src;
            src++;
            continue;
        }

        if (',' == last)
        {
            buf[i++] = 0x20; // Space
        }
        buf[i++] = 0x9 == *src ? ' ' : *src; // Tab
        last = *src;
        src++;
    }
    buf[i] = 0x0;
    length = strlen(buf) + 1;
    res = (char *)calloc(length, sizeof(char));
    strncpy(res, buf, length);
    return res;
}

void printGadget(struct gadget_t *gadget)
{
    if (gadget->length > 0)
    {
        char *prettified;
        int8_t i;

        for (i = gadget->length - 1; i >= 0; i--)
        {
            prettified = prettifyString(gadget->instructions[i]->disassembled);
            if (gadget->length - 1 == i)
            {
                printf("%#010x:%c", gadget->instructions[i]->address, 0x20);
            }

            if (0 == i)
            {
                printf("%s;", prettified);
            }

            else
            {
                printf("%s;%c", prettified, 0x20);
            }
            free(prettified);
            prettified = NULL;
        }
        putchar(0x0a); // Newline
    }
}

// Generates a key where the number X (addi sp, sp, X) is gone
static char *updateKey(char *key)
{
    size_t index = strlen(key);
    char *aux = strdup(key);
    char *last = &aux[index - 1];

    while (*last != 0x20)
    {
        last--;
    }

    memset(last, 0x0, strlen(last));
    memcpy(last, "ret", 3);
    return aux;
}