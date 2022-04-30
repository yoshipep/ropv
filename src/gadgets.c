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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "datatypes.h"
#include "gadgets.h"

static void printGadget(gadget_t *gadget);

static __attribute__((always_inline)) inline uint8_t checkValidity(ins32_t *instruction);

static __attribute__((always_inline)) inline uint8_t checkValidity(ins32_t *instruction)
{
    return instruction->operation != CMP && instruction->operation != JMP &&
           instruction->operation != BRK && instruction->operation != STORE &&
           instruction->operation != RET && !strstr(instruction->disassembled, "auipc");
}

void processGadgets(uint8_t lastElement)
{

    if (verbose)
    {
        puts("[+] Selecting gadgets");
    }

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
}

static void printGadget(gadget_t *gadget)
{

    int8_t i;

    for (i = gadget->length - 1; i >= 0; i--)
    {
        if (gadget->length - 1 == i)
        {
            printf("%#08x:", gadget->instructions[i]->address);
        }
        printf("%s;", gadget->instructions[i]->disassembled);
    }
    printf("\n");
}
