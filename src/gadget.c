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

#include "instructions.h"
#include "gadget.h"
#include "node.h"

#define MAX_LENGTH_NO_RET 6

struct instruction *preliminary_gadget_list[100];

struct node_t *list;

struct node_t *spDuplicated;

static struct node_t *last = NULL;

static struct node_t *lastSp = NULL;

static bool checkValidity(struct instruction *instruction);

static char *generateKey(struct gadget_t *gadget);

static inline bool isLastInstruction(struct instruction *instruction);

static struct gadget_t *jopFilter(struct gadget_t *gadget);

static bool messSp(struct instruction *instruction);

static struct gadget_t *noRetFilter(uint16_t lastElement);

static struct gadget_t *retFilter(uint16_t lastElement);

static char *updateKey(char *key);

void printGadget(struct gadget_t *gadget)
{
	if (gadget->length > 0) {
		int8_t i;

		for (i = gadget->length - 1; i >= 0; i--) {
			if (gadget->length - 1 == i) {
				if (0 == gadget->instructions[i]->addr.addr32) {
					printf("%#010lx:%c",
					       gadget->instructions[i]
						       ->addr.addr64,
					       0x20);
				} else {
					printf("%#010x:%c",
					       gadget->instructions[i]
						       ->addr.addr32,
					       0x20);
				}
			}

			if (0 == i) {
				printf("%s;",
				       gadget->instructions[i]->disassembled);
			}

			else {
				printf("%s;%c",
				       gadget->instructions[i]->disassembled,
				       0x20);
			}
		}
		putchar(0x0a); // Newline
	}
}

void processGadgets(uint8_t lastElement, op_t lastOperation)
{
	char *key, *tmp, *newKey;
	uint8_t index;
	struct node_t *found;
	struct gadget_t *gadget;

	switch (lastOperation) {
	case RET:
	default:
		gadget = retFilter(lastElement);
		break;
	case SYSCALL:
		gadget = noRetFilter(lastElement);
		break;
	case JMP:
		gadget = noRetFilter(lastElement);
		gadget = jopFilter(gadget);
		break;
	}

	if ((NULL != gadget) || (NULL != gadget && gadget->length > 0)) {
		if (NULL == last) {
			last = list;
		}
		key = generateKey(gadget);

		for (index = 0; index < gadget->length; index++) {
			if ((ADD == gadget->instructions[index]->operation) &&
			    (gadget->instructions[index]->useImmediate) &&
			    (0 == strcmp(gadget->instructions[index]->regDest,
					 "sp"))) {
				break;
			}
		}

		if ((gadget->length >= 2) && (index < gadget->length)) {
			if (NULL == lastSp) {
				lastSp = spDuplicated;
			}
			newKey = updateKey(key);
			found = find(spDuplicated, newKey);

			if (NULL == found) {
				lastSp = insert(lastSp, gadget, newKey);
				last = insert(last, gadget, key);
			}

			else {
				if (found->data->instructions[index]->immediate >
				    gadget->instructions[index]->immediate) {
					tmp = generateKey(found->data);
					update(found, gadget, newKey);
					del(list, tmp);
					free(tmp);
					tmp = NULL;
				}
			}
			free(newKey);
			newKey = NULL;
		} else {
			if (NULL == find(list, key)) {
				last = insert(last, gadget, key);
			}
		}
		free(key);
		key = NULL;
	}
}

static bool checkValidity(struct instruction *instruction)
{
	return (CMP != instruction->operation) &&
	       (JMP != instruction->operation) &&
	       (BRK != instruction->operation) &&
	       (RET != instruction->operation) &&
	       (CALL != instruction->operation) &&
	       (SYSCALL != instruction->operation) &&
	       (UNSUPORTED != instruction->operation) &&
	       (ATOMIC != instruction->operation) &&
	       (IO != instruction->operation) &&
	       !strstr(instruction->disassembled, "auipc") &&
	       !messSp(instruction);
}

// Generates a key where all the instructions have no separation
static char *generateKey(struct gadget_t *gadget)
{
	int8_t i;
	size_t length;
	uint16_t index = 0;
	char *buf = (char *)calloc(700, sizeof(char));

	for (i = gadget->length - 1; i >= 0; i--) {
		length = strlen(gadget->instructions[i]->disassembled);
		strncpy(&buf[index], gadget->instructions[i]->disassembled,
			length);
		index += length;
	}
	return buf;
}

static inline bool isLastInstruction(struct instruction *instruction)
{
	return (LOAD == instruction->operation) &&
	       (0 == strcmp(instruction->regDest, "ra"));
}

static struct gadget_t *jopFilter(struct gadget_t *gadget)
{
	int8_t i;
	const char *refRegister;
	uint8_t nCoindicendes = 0;
	refRegister = gadget->instructions[0]->regDest;

	for (i = gadget->length - 1; i >= 1; i--) {
		if (0 ==
		    strcmp(refRegister, gadget->instructions[i]->regDest)) {
			nCoindicendes++;
		}
	}

	if (nCoindicendes >= (gadget->length / 2)) {
		free(gadget);
		return NULL;
	}
	return gadget;
}

static bool messSp(struct instruction *instruction)
{
	return ((ADD == instruction->operation) && instruction->useImmediate &&
		(instruction->immediate < 0) &&
		strstr(instruction->disassembled, "addi\tsp")) ||
	       ((SUB == instruction->operation) &&
		strstr(instruction->disassembled, "sub\tsp"));
}

static struct gadget_t *noRetFilter(uint16_t lastElement)
{
	uint16_t current;
	struct gadget_t *gadget =
		(gadget_t *)calloc(1, sizeof(struct gadget_t));

	gadget->instructions[0] = preliminary_gadget_list[lastElement];
	gadget->length = 1;
	current = 0 == lastElement ? 99 : lastElement - gadget->length;
	while (gadget->length < MAX_LENGTH_NO_RET &&
	       checkValidity(preliminary_gadget_list[current])) {
		gadget->instructions[gadget->length] =
			preliminary_gadget_list[current];
		gadget->length++;
		if (0 == current) {
			current = 99;
		}

		else {
			current--;
			if (0 == current)
				current = 99;
		}
	}
	return gadget;
}

static struct gadget_t *retFilter(uint16_t lastElement)
{
	uint16_t current;
	struct gadget_t *gadget =
		(gadget_t *)calloc(1, sizeof(struct gadget_t));

	gadget->instructions[0] = preliminary_gadget_list[lastElement];
	gadget->length = 1;
	current = 0 == lastElement ? 99 : lastElement - gadget->length;
	while (gadget->length < MAX_LENGTH &&
	       checkValidity(preliminary_gadget_list[current]) &&
	       !isLastInstruction(preliminary_gadget_list[current])) {
		gadget->instructions[gadget->length] =
			preliminary_gadget_list[current];
		gadget->length++;
		if (0 == current) {
			current = 99;
		}

		else {
			current--;
			if (0 == current)
				current = 99;
		}
	}

	if (isLastInstruction(preliminary_gadget_list[current])) {
		gadget->instructions[gadget->length] =
			preliminary_gadget_list[current];
		gadget->length++;
		return gadget;
	}
	free(gadget);
	return NULL;
}

// Generates a key where the number X (addi sp, sp, X) is gone
static char *updateKey(char *key)
{
	size_t index = strlen(key);
	char *aux = strdup(key);
	char *last = &aux[index - 1];

	while (*last != 0x20) {
		last--;
	}

	memset(last, 0x0, strlen(last));
	memcpy(last, "ret", 3);
	return aux;
}