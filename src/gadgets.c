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

static ins32_t preliminary_gadget_list[100];

static void setInmediate(struct ins32_t *instruction);

static void setShift(struct ins32_t *instruction);

static __attribute__((always_inline)) inline uint8_t pushToPGL(struct ins32_t instruction);

static __attribute__((always_inline)) inline uint8_t pushToPGL(struct ins32_t instruction)
{
    static size_t pos = 0;
    preliminary_gadget_list[pos % 100] = instruction;
    return (uint8_t)pos++ % 100;
}

void fillData(struct ins32_t *instruction)
{
    char start = instruction->disassembled[0];

    switch (start)
    {
    case 'l':
        instruction->operation = LOAD;
        instruction->mode = 0b0011;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;

    case 'b':
        instruction->operation = CMP;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;

    case 'j':
        instruction->operation = JMP;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;

    case 'x':
        instruction->operation = XOR;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
            setInmediate(instruction);
        }

        instruction->useImmediate = 0;
        break;

    case 'o':
        instruction->operation = OR;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
            setInmediate(instruction);
        }

        instruction->useImmediate = 0;
        break;

    case 'e':
        if (strstr(instruction->disassembled, "ecall"))
        {
            instruction->operation = CALL;
        }

        else
        {
            instruction->operation = BRK;
        }

        instruction->useShift = 0;
        instruction->useImmediate = 0;
        instruction->mode = 0;
        break;

    case 'r':
        instruction->operation = RET;
        instruction->useShift = 0;
        instruction->useImmediate = 0;
        break;

    case 'n':
        if (strstr(instruction->disassembled, "t"))
        {
            instruction->operation = NOT;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
            instruction->mode = 0b0011;
            break;
        }
        else if (strstr(instruction->disassembled, "g"))
        {
            instruction->operation = NEG;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
            instruction->mode = 0b0011;
            break;
        }
        else
        {
            instruction->operation = NOP;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
            instruction->mode = 0;
            break;
        }

    case 'm':
        instruction->operation = MOV;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        instruction->useImmediate = 0;
        break;

    case 'a':
        if (strstr(instruction->disassembled, "ad") || strstr(instruction->disassembled, "au"))
        {
            instruction->operation = ADD;
            instruction->mode = 0b0011;
        }

        else
        {
            instruction->operation = AND;
            instruction->mode = 0b0011;
        }

        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
            setInmediate(instruction);
        }

        instruction->useImmediate = 0;

        break;

    case 's':
        if (strstr(instruction->disassembled, "sub"))
        {
            instruction->operation = SUB;
            instruction->mode = 0b0011;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
        }

        else if (strstr(instruction->disassembled, "se") || strstr(instruction->disassembled, "slt") || strstr(instruction->disassembled, "sn") || strstr(instruction->disassembled, "sg"))
        {
            instruction->operation = SET;
            instruction->mode = 0b0011;
            instruction->useShift = 0;
            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = 1;
                setInmediate(instruction);
            }

            instruction->useImmediate = 0;
        }

        else if (strstr(instruction->disassembled, "sr") || strstr(instruction->disassembled, "sll"))
        {
            instruction->operation = SHIFT;
            instruction->mode = 0b0011;
            instruction->useShift = 1;
            setShift(instruction);
            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = 1;
                setInmediate(instruction);
            }

            instruction->useImmediate = 0;
        }

        else
        {
            instruction->operation = STORE;
            instruction->mode = 0b1100;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
        }
        break;

    default:
        return;
    }

    pushToPGL(*instruction);
}

static void setInmediate(struct ins32_t *instruction)
{
    char *dummy;
    size_t size;
    size_t startPos = strlen(instruction->disassembled) - 1;
    char *isPresent = strstr(instruction->disassembled, "0x");

    if (isPresent)
    {
        size = startPos - (&instruction->disassembled[startPos] - isPresent);
        dummy = (char *)malloc(sizeof(char) * size);

        strncpy(dummy, &instruction->disassembled[size + 2], size);
        instruction->immediate = atoi(dummy);
        goto liberate;
    }

    while (instruction->disassembled[startPos - 1] != ',')
    {
        startPos--;
    }

    dummy = (char *)malloc(sizeof(char) * (strlen(instruction->disassembled) - startPos));
    strncpy(dummy, &instruction->disassembled[startPos], startPos);
    instruction->immediate = atoi(dummy);

liberate:
    free(dummy);
    dummy = NULL;
}

static void setShift(struct ins32_t *instruction)
{
    char *pos = strstr(instruction->disassembled, ",");
    instruction->regToShift[2] = 0;

    strncpy(instruction->regToShift, ++pos, 2);

    if (strstr(instruction->disassembled, "srli"))
    {
        instruction->type = SRLI;
    }

    else if (strstr(instruction->disassembled, "slli"))
    {
        instruction->type = SLLI;
    }

    else if (strstr(instruction->disassembled, "sll"))
    {
        instruction->type = SLL;
    }

    else if (strstr(instruction->disassembled, "srl"))
    {
        instruction->type = SRL;
    }

    else if (strstr(instruction->disassembled, "sra"))
    {
        instruction->type = SRA;
    }

    else
    {
        instruction->type = SRAI;
    }
}

void processGadgets()
{

    switch (arguments.mode)
    {
    case FULL_MODE:
        break;
    case INTEREST_MODE:
        break;
    case SPECIFIC_MODE:
        break;
    default:
        break;
    }
}