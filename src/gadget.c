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

static struct node_t *last = NULL;

void printGadget(struct gadget_t *gadget);

static char *prettifyString(char *src);

static void basicFilter(uint8_t lastElement, uint8_t insProcessed, struct gadget_t *gadget);

static void advancedFilter(struct gadget_t *gadget);

static struct gadget_t *jopFilter(struct gadget_t *gadget);

static char *generateKey(struct gadget_t *gadget);

static bool checkValidity(struct ins32_t *instruction);

static inline bool messSp(struct ins32_t *instruction);

static bool checkValidity(struct ins32_t *instruction)
{
    return (CMP != instruction->operation) && (JMP != instruction->operation) &&
           (BRK != instruction->operation) && (RET != instruction->operation) &&
           (CALL != instruction->operation) &&
           (UNSUPORTED != instruction->operation) &&
           (ATOMIC != instruction->operation) && (IO != instruction->operation) &&
           !strstr(instruction->disassembled, "auipc") && !messSp(instruction);
}

static inline bool messSp(struct ins32_t *instruction)
{
    return (ADD == instruction->operation && instruction->useImmediate &&
            instruction->immediate < 0 &&
            strstr(instruction->disassembled, "addi\tsp")) ||
           (SUB == instruction->operation &&
            strstr(instruction->disassembled, "sub\tsp"));
}

static void basicFilter(uint8_t lastElement, uint8_t insProcessed, struct gadget_t *gadget)
{
    uint8_t current;

    gadget->instructions[0] = preliminary_gadget_list[lastElement];
    gadget->length = 1;
    current = 0 == lastElement ? 99 : lastElement - gadget->length;
    while (gadget->length < insProcessed && checkValidity(preliminary_gadget_list[current]))
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
}

static void advancedFilter(struct gadget_t *gadget)
{
    int8_t i = gadget->length - 1;

    for (; i >= 0; i--)
    {
        if (('a' == gadget->instructions[i]->regDest[0]) &&
            ('6' != gadget->instructions[i]->regDest[1]))
        {
            return;
        }

        else
        {
            gadget->length -= 1;
            if (gadget->instructions[i]->isCompressed)
            {
                gadget->instructions[i]->address += 2;
            }

            else
            {
                gadget->instructions[i]->address += 4;
            }
        }
    }
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

void processGadgets(uint8_t lastElement, uint8_t insProcessed, op_t lastOperation)
{
    char *key;
    struct gadget_t *gadget = (gadget_t *)malloc(sizeof(struct gadget_t));

    basicFilter(lastElement, insProcessed, gadget);

    switch (lastOperation)
    {
    case RET:

        if (INTEREST_MODE == args.mode)
        {
            advancedFilter(gadget);
        }
        break;

    case JMP:
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

        if (!find(list, key))
        {
            last = insert(last, gadget, key);
        }
        free(key);
        key = NULL;
    }
}

static char *generateKey(struct gadget_t *gadget)
{
    int8_t i;
    size_t length;
    char *prettified;
    uint8_t index = 0;
    char *buf = (char *)calloc(150, sizeof(char));

    for (i = gadget->length - 1; i >= 0; i--)
    {
        prettified = prettifyString(gadget->instructions[i]->disassembled);
        length = strlen(prettified);
        strncpy(&buf[index], prettified, length);
        index += length;
        free(prettified);
        prettified = NULL;
    }
    return buf;
}

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
        free(gadget);
        gadget = NULL;
    }
}