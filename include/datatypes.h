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

#include <stdint.h>

typedef uint32_t addr32_t;

/*Todos los gadgets, los más interesantes, todos los relacionados con x registro*/
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
    RET
} op_t;

typedef enum
{
    SRLI,
    SLLI,
    SLL,
    SRL,
    SRA,
    SRAI
} shift_t;

struct arguments
{
    char *file;
    program_mode_t mode;
    uint8_t arg_num;
};

typedef struct ins32_t
{
    addr32_t address;
    int16_t immediate;
    uint8_t mode;
    uint8_t useImmediate;
    shift_t type;
    op_t operation;
    char *disassembled;
    uint8_t useShift;
    char regToShift[3];
} ins32_t;

#endif