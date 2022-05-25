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

static char *trim(char *str);

static void basicFilter(uint8_t lastElement, struct gadget_t *gadget);

static void advancedFilter(struct gadget_t *gadget);

static __attribute__((always_inline)) inline uint8_t checkValidity(ins32_t *instruction);

static __attribute__((always_inline)) inline uint8_t messSp(ins32_t *instruction);

static inline uint8_t checkValidity(ins32_t *instruction)
{
    if (args.options)
    {
        return (CMP != instruction->operation) &&
               (BRK != instruction->operation) && (RET != instruction->operation) &&
               (ATOMIC != instruction->operation) && (IO != instruction->operation) &&
               !strstr(instruction->disassembled, "auipc") && !messSp(instruction);
    }
    return (CMP != instruction->operation) && (JMP != instruction->operation) &&
           (BRK != instruction->operation) && (RET != instruction->operation) &&
           (ATOMIC != instruction->operation) && (IO != instruction->operation) &&
           !strstr(instruction->disassembled, "auipc") && !messSp(instruction);
}

static inline uint8_t messSp(ins32_t *instruction)
{
    return (ADD == instruction->operation && instruction->useImmediate &&
            instruction->immediate < 0 &&
            strstr(instruction->disassembled, "addi\tsp")) ||
           (SUB == instruction->operation &&
            strstr(instruction->disassembled, "sub\tsp"));
}

static void basicFilter(uint8_t lastElement, gadget_t *gadget)
{
    uint8_t current;
    gadget->instructions[0] = preliminary_gadget_list[lastElement];
    gadget->length = 1;
    current = 0 == lastElement ? 99 : lastElement - gadget->length;
    while (gadget->length < MAX_LENGTH && checkValidity(preliminary_gadget_list[current]))
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

void processGadgets(uint8_t lastElement)
{

    char buf[150];
    char *prettified;
    int8_t i;
    size_t length;
    uint8_t index = 0;
    struct gadget_t *gadget = (gadget_t *)malloc(sizeof(struct gadget_t));

    basicFilter(lastElement, gadget);

    if (INTEREST_MODE == args.mode)
    {
        advancedFilter(gadget);
    }
    memset(buf, 0x0, sizeof(char) * 150);

    for (i = gadget->length - 1; i >= 0; i--)
    {
        prettified = prettifyString(gadget->instructions[i]->disassembled);
        length = strlen(prettified);
        strncpy(&buf[index], prettified, length);
        index += length;
    }

    if (NULL == last)
    {
        last = list;
    }

    if (!find(list, buf))
    {
        last = insert(last, gadget, buf);
    }

    // printGadget(gadget);
}

static char *trim(char *str)
{
    char *aux;
    while (isspace((unsigned char)*str))
    {
        str++;
    }

    if (0 == *str)
    {
        return str;
    }
    aux = str + strlen(str) - 1;
    while (aux > str && isspace((unsigned char)*aux))
    {
        aux--;
    }

    aux[1] = 0x0;

    return str;
}

static char *prettifyString(char *src)
{
    char last, *res, buf[50];
    uint8_t length;
    uint8_t i = 0;

    char *trimmed = trim(src);
    while (*trimmed)
    {
        if (0x20 == *trimmed && 0x20 == last)
        {
            last = *trimmed;
            trimmed++;
            continue;
        }

        if (',' == last)
        {
            buf[i++] = 0x20; // Space
        }
        buf[i++] = 0x9 == *trimmed ? ' ' : *trimmed; // Tab
        last = *trimmed;
        trimmed++;
    }
    buf[i] = 0x0;
    length = strlen(buf) + 1;
    res = (char *)malloc(length * sizeof(char));
    strncpy(res, buf, length);
    res[length - 1] = 0x0;
    return res;
}

void printGadget(struct gadget_t *gadget)
{
    if (gadget->length > 0)
    {
        int8_t i;

        for (i = gadget->length - 1; i >= 0; i--)
        {
            char *prettified = prettifyString(gadget->instructions[i]->disassembled);
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
        }
        putchar(0x0a); // Newline
    }
}
