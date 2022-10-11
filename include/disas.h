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
#define _DISAS_H

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>

struct mappedBin {
	char *address;
	off_t size;
};

extern struct instruction *preliminary_gadget_list[100];

extern struct node_t *list;

extern struct node_t *spDuplicated;

uint8_t process_elf(char *elfFile);

static __attribute__((always_inline)) inline void
unmapFile(struct mappedBin *file) {
	munmap(file->address, file->size);
}

#endif