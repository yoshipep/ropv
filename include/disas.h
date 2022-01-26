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

#ifndef _DISAS_H
#define _DISAS_H 1

#define DEFAULT_PERM 0644

#include <elf.h>

typedef uint32_t addr32_t;
typedef uint64_t addr64_t;

inline uint8_t checkArch(Elf32_Half arch);

inline uint8_t getBits(Elf32_Ehdr *header);

uint8_t process_elf(const char *elfFile);

uint8_t disassemble(const char *elfFile);

uint8_t parseContent(const char *assemblyFile);

typedef struct
{
    addr32_t address;
    uint32_t opcode;

} ins32_t;

typedef struct
{
    addr64_t address;
    uint32_t opcode;

} ins64_t;

#endif