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

#define DEFAULT_LENGTH 3

typedef uint32_t addr32_t;
typedef uint64_t addr64_t;

/*Todos los gadgets, los más interesantes, todos los relacionados con x registro*/
typedef enum
{
    FULL_MODE,
    INTEREST_MODE,
    SPECIFIC_MODE
} program_mode_t;

typedef enum
{
    LOAD,
    STORE,
    CMP,
    JMP,
    ADD,
    XOR,
    OR,
    AND,
    SHIFT,
    SUB,
    SET,
    NOP,
    MOV,
    CALL,
    BRK
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
    uint8_t length;
    char *file;
    program_mode_t mode;
    uint8_t arg_num;
};

/*Necesitamos saber: direccion, efecto (salto, suma, resta...), si tiene inmediato, si es de tipo shift, si es de R/W
ins desensamblada*/
typedef struct ins32_t
{
    addr32_t address;  /*int y = 0x103c0;printf("0x%08x\n", y);*/
    int16_t immediate; // Used by I-Type instructions
    uint8_t mode;      // Read = 0xC -> HI, Write = 3 -> LO
    uint8_t useImmediate;
    uint8_t useShift;
    uint8_t regToShift; // Register where the result is written
    shift_t type; // Type of shift
    op_t operation;
    char *disassembled;
} ins32_t;

#endif