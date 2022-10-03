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

#ifndef _ROPV_H
#define _ROPV_H

#include <stdint.h>

typedef enum
{
	GENERIC_MODE,
	JOP_MODE,
	RET_MODE,
	SYSCALL_MODE
} program_mode_t;

struct arguments
{
	char *file;
	program_mode_t mode;
	uint8_t arg_num;
	uint8_t options;
};

#endif