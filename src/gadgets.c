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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "datatypes.h"
#include "gadgets.h"

static inline __attribute__((always_inline)) uint8_t checkValidity(ins32_t *instruction);

static inline __attribute__((always_inline)) uint8_t checkValidity(ins32_t *instruction)
{
    return instruction->operation == CMP || instruction->operation == JMP ||
           instruction->operation == BRK || instruction->operation == STORE ||
           instruction->operation == RET || !strstr(instruction->disassembled, "auipc");
}

void processGadgets()
{
    uint8_t i;
    gadget_t *gadget = (gadget_t *)malloc(sizeof(gadget_t));
    switch (args.mode)
    {
    case FULL_MODE:
        i = 99;
        gadget->length = 0;

        while (i > 94 || !checkValidity(preliminary_gadget_list[i]))
        {
            gadget->instructions[gadget->length] = preliminary_gadget_list[i];
            gadget->length++;
            i--;
        }
        break;
    case INTEREST_MODE:
        break;
    default:
        break;
    }
}