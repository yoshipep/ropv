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
#include "gadgets.h"

static void printGadget(gadget_t *gadget);

static char *prettifyString(char *src);

static char *trim(char *str);

static __attribute__((always_inline)) inline uint8_t checkValidity(ins32_t *instruction);

static __attribute__((always_inline)) inline uint8_t checkValidity(ins32_t *instruction)
{
    return instruction->operation != CMP && instruction->operation != JMP &&
           instruction->operation != BRK && instruction->operation != STORE &&
           instruction->operation != RET && !strstr(instruction->disassembled, "auipc");
}

void processGadgets(uint8_t lastElement)
{
    gadget_t *gadget = (gadget_t *)malloc(sizeof(gadget_t));
    switch (args.mode)
    {
    case GENERIC_MODE:
        gadget->length = 0;
        gadget->instructions[gadget->length++] = preliminary_gadget_list[lastElement];
        while (gadget->length < MAX_LENGTH && checkValidity(preliminary_gadget_list[lastElement - gadget->length]))
        {
            gadget->instructions[gadget->length] = preliminary_gadget_list[lastElement - gadget->length];
            gadget->length++;
        }
        break;
    case INTEREST_MODE:
        break;
    default:
        break;
    }
    printGadget(gadget);
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

    aux[1] = '\0';

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
            buf[i++] = 0x20;
        }
        buf[i++] = 0x9 == *trimmed ? ' ' : *trimmed;
        last = *trimmed;
        trimmed++;
    }
    buf[i] = 0;
    length = strlen(buf) + 1;
    res = (char *)malloc(length * sizeof(char));
    strncpy(res, buf, length);
    res[length - 1] = 0x0;
    return res;
}

static void printGadget(gadget_t *gadget)
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
    putchar(0x0a);
}
