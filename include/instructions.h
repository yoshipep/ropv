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

#ifndef _INSTRUCTIONS_H
#define _INSTRUCTIONS_H

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t addr32_t;
typedef uint64_t addr64_t;

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
	SYSCALL,
	BRK,
	NOT,
	NEG,
	RET,
	ATOMIC,
	IO,
	MUL,
	DIV,
	UNSUPORTED
} op_t;

typedef union address {
		addr32_t addr32;
		addr64_t addr64;
	} address;

typedef struct instruction
{
	union address addr;
	int16_t immediate;
	bool useImmediate;
	bool useShift;
	op_t operation;
	const char *disassembled;
	const char *regToShift;
	const char *regDest;
} instruction;

#endif