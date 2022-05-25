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

#ifndef _DATATYPES_H
#define _DATATYPES_H 1

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t addr32_t;

typedef enum
{
    GENERIC_MODE,
    INTEREST_MODE
} program_mode_t;

typedef enum
{
    LOAD,
    STORE,
    CMP,
    JMP,
    ADD,
    OR,
    AND,
    SHIFT,
    SUB,
    SET,
    NOP,
    MOV,
    CALL,
    BRK,
    NOT,
    NEG,
    RET,
    ATOMIC,
    IO,
    MUL,
    DIV
} op_t;

struct arguments
{
    char *file;
    program_mode_t mode;
    uint8_t arg_num;
    uint8_t options;
};

typedef struct ins32_t
{
    addr32_t address;
    int16_t immediate;
    bool useImmediate;
    bool isCompressed;
    op_t operation;
    char *disassembled;
    char regToShift[3];
    char regDest[3];
} ins32_t;

#endif