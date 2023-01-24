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

struct node_t *list = NULL;

struct node_t *spDuplicated = NULL;

static struct node_t *last = NULL;

static struct node_t *lastSp = NULL;

static bool checkValidity(struct instruction *ins);

static char *generateKey(struct gadget_t *g);

static bool isAddInstruction(enum riscv_insn *op);

static inline bool isAtomicInstruction(enum riscv_insn *op);

static inline bool isBreakInstruction(enum riscv_insn *op);

static bool isCmpInstruction(enum riscv_insn *op);

static bool isIOInstruction(enum riscv_insn *op);

static bool isJumpInstruction(enum riscv_insn *op);

static bool isLastInstruction(struct instruction *ins);

static bool isLoadInstruction(enum riscv_insn *op);

static bool isSubInstruction(enum riscv_insn *op);

static struct gadget_t *jopFilter(struct gadget_t *g);

static bool messSp(struct instruction *ins);

static struct gadget_t *noRetFilter(uint8_t lastElement);

static struct gadget_t *retFilter(uint8_t lastElement);

static char *updateKey(char *key);

void printGadget(struct gadget_t *g)
{
	if (g->length > 0) {
		int8_t i;
		for (i = g->length - 1; i >= 0; i--) {
			if ((g->length - 1 == i) &&
			    (0 == g->instructions[i]->addr.addr32)) {
				printf("%#010lx:%c",
				       g->instructions[i]->addr.addr64, 0x20);
			} else if ((g->length - 1 == i) &&
				   (0 != g->instructions[i]->addr.addr32)) {
				printf("%#010x:%c",
				       g->instructions[i]->addr.addr32, 0x20);
			}
			if (0 == i)
				printf("%s;", g->instructions[i]->disassembled);
			else
				printf("%s;%c",
				       g->instructions[i]->disassembled, 0x20);
		}
		putchar(0x0a); // Newline
	}
}

void processGadgets(uint8_t lastElem, enum riscv_insn lastOp)
{
	char *key, *tmp, *newKey;
	uint8_t index;
	struct node_t *found;
	struct gadget_t *g;
	switch (lastOp) {
	case 0:
	default:
		g = retFilter(lastElem);
		break;
	case RISCV_INS_ECALL:
		g = noRetFilter(lastElem);
		break;
	case RISCV_INS_C_JALR:
	case RISCV_INS_JALR:
		g = noRetFilter(lastElem);
		g = jopFilter(g);
		break;
	}
	if ((NULL != g) || (NULL != g && g->length > 0)) {
		if (NULL == last)
			last = list;
		key = generateKey(g);
		for (index = 0; index < g->length; index++) {
			if ((isAddInstruction(
				    &g->instructions[index]->operation)) &&
			    (g->instructions[index]->useImmediate) &&
			    (0 ==
			     strcmp(g->instructions[index]->regDest, "sp")))
				break;
		}
		if ((g->length >= 2) && (index < g->length)) {
			if (NULL == lastSp)
				lastSp = spDuplicated;
			newKey = updateKey(key);
			found = find(spDuplicated, newKey);
			if (NULL == found) {
				lastSp = insert(lastSp, g, newKey);
				last = insert(last, g, key);
			} else {
				if (found->data->instructions[index]->immediate >
				    g->instructions[index]->immediate) {
					tmp = generateKey(found->data);
					update(found, g, newKey);
					del(list, tmp);
					free(tmp);
					tmp = NULL;
				}
			}
			free(newKey);
			newKey = NULL;
		} else if (NULL == find(list, key)) {
			last = insert(last, g, key);
		}
		free(key);
		key = NULL;
	}
}

static bool checkValidity(struct instruction *ins)
{
	return (!isCmpInstruction(&ins->operation)) &&
	       (!isJumpInstruction(&ins->operation)) &&
	       (!isBreakInstruction(&ins->operation)) &&
	       (RISCV_INS_ECALL != ins->operation) &&
	       (RISCV_INS_INVALID != ins->operation) &&
	       (!isAtomicInstruction(&ins->operation)) &&
	       (!isIOInstruction(&ins->operation)) &&
	       (!strstr(ins->disassembled, "auipc")) && (!messSp(ins));
}

// Generates a key where all the instructions have no separation
static char *generateKey(struct gadget_t *g)
{
	int8_t i;
	size_t length;
	uint16_t index = 0;
	char *buf = (char *)calloc(700, sizeof(char));
	for (i = g->length - 1; i >= 0; i--) {
		length = strlen(g->instructions[i]->disassembled);
		strncpy(&buf[index], g->instructions[i]->disassembled, length);
		index += length;
	}
	return buf;
}

static bool isAddInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_ADD == *op) || (RISCV_INS_ADDI == *op) ||
	       (RISCV_INS_ADDIW == *op) || (RISCV_INS_ADDW == *op) ||
	       (RISCV_INS_C_ADD == *op) || (RISCV_INS_C_ADDI == *op) ||
	       (RISCV_INS_C_ADDIW == *op) || (RISCV_INS_C_ADDW == *op) ||
	       (RISCV_INS_C_ADDI16SP == *op) || (RISCV_INS_C_ADDI4SPN == *op);
}

static inline bool isAtomicInstruction(enum riscv_insn *op)
{
	/*5 = RISCV_INS_AMOADD_D, 76 = RISCV_INS_AMOXOR_W_RL*/
	return (5 >= *op) && (76 <= *op);
}

static inline bool isBreakInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_C_EBREAK == *op) || (RISCV_INS_EBREAK == *op);
}

static bool isCmpInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_BEQ == *op) || (RISCV_INS_BGE == *op) ||
	       (RISCV_INS_BGEU == *op) || (RISCV_INS_BLT == *op) ||
	       (RISCV_INS_BLTU == *op) || (RISCV_INS_BNE == *op) ||
	       (RISCV_INS_C_BEQZ == *op) || (RISCV_INS_C_BNEZ == *op);
}

static bool isIOInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_FENCE == *op) || (RISCV_INS_FENCE_I == *op) ||
	       (RISCV_INS_FENCE_TSO == *op) || (RISCV_INS_SFENCE_VMA == *op);
}

static bool isJumpInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_C_J == *op) || (RISCV_INS_C_JAL == *op) ||
	       (RISCV_INS_C_JALR == *op) || (RISCV_INS_C_JR == *op) ||
	       (RISCV_INS_JAL == *op) || (RISCV_INS_JALR == *op);
}

static bool isLastInstruction(struct instruction *ins)
{
	return (isLoadInstruction(&ins->operation)) &&
	       (0 == strcmp(ins->regDest, "ra"));
}

static bool isLoadInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_LB == *op) || (RISCV_INS_LBU == *op) ||
	       (RISCV_INS_LH == *op) || (RISCV_INS_LHU == *op) ||
	       (RISCV_INS_C_LW == *op) || (RISCV_INS_LW == *op) ||
	       (RISCV_INS_LWU == *op) || (RISCV_INS_C_LWSP == *op);
}

static bool isSubInstruction(enum riscv_insn *op)
{
	return (RISCV_INS_SUB == *op) || (RISCV_INS_SUBW == *op) ||
	       (RISCV_INS_C_SUB == *op) || (RISCV_INS_C_SUBW == *op);
}

static struct gadget_t *jopFilter(struct gadget_t *g)
{
	int8_t i;
	const char *refRegister = g->instructions[0]->regDest;
	uint8_t coincidences = 0;
	for (i = g->length - 1; i >= 1; i--) {
		if (0 == strcmp(refRegister, g->instructions[i]->regDest))
			coincidences++;
	}
	if (coincidences >= (g->length / 2)) {
		free(g);
		g = NULL;
		return NULL;
	}
	return g;
}

static bool messSp(struct instruction *ins)
{
	return (((isAddInstruction(&ins->operation)) && ins->useImmediate &&
		 (ins->immediate < 0)) ||
		(isSubInstruction(&ins->operation))) &&
	       (0 == strcmp("sp", ins->regDest));
}

static struct gadget_t *noRetFilter(uint8_t lastElement)
{
	uint8_t current;
	struct gadget_t *g =
		(struct gadget_t *)calloc(1, sizeof(struct gadget_t));
	g->instructions[0] = preliminary_gadget_list[lastElement];
	g->length = 1;
	current = 0 == lastElement ? 99 : lastElement - g->length;
	while (g->length < MAX_LENGTH_NO_RET &&
	       checkValidity(preliminary_gadget_list[current])) {
		g->instructions[g->length] = preliminary_gadget_list[current];
		g->length++;
		if (0 == current) {
			current = 99;
		} else {
			current--;
			if (0 == current)
				current = 99;
		}
	}
	return g;
}

static struct gadget_t *retFilter(uint8_t lastElement)
{
	uint8_t current;
	struct gadget_t *g =
		(struct gadget_t *)calloc(1, sizeof(struct gadget_t));
	g->instructions[0] = preliminary_gadget_list[lastElement];
	g->length = 1;
	current = 0 == lastElement ? 99 : lastElement - g->length;
	while (g->length < MAX_LENGTH &&
	       checkValidity(preliminary_gadget_list[current]) &&
	       !isLastInstruction(preliminary_gadget_list[current])) {
		g->instructions[g->length] = preliminary_gadget_list[current];
		g->length++;
		if (0 == current) {
			current = 99;
		} else {
			current--;
			if (0 == current)
				current = 99;
		}
	}
	if (isLastInstruction(preliminary_gadget_list[current])) {
		g->instructions[g->length] = preliminary_gadget_list[current];
		g->length++;
		return g;
	}
	free(g);
	g = NULL;
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