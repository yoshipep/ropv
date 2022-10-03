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

#include <capstone/capstone.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "instructions.h"
#include "disas.h"
#include "errors.h"
#include "gadget.h"
#include "node.h"
#include "ropv.h"

static csh handle;

static bool is64Bit;

static int disas(unsigned char *opcode, uint64_t address);

static int dumpCode(Elf32_Shdr *sect, char *mappedBin);

static uint8_t fillData(struct instruction *instruction, cs_detail *detail);

static void getOpcode(int opcode, unsigned char *opcode_ptr);

static struct mappedBin *mapFile(FILE *file);

static uint8_t pushToPGL(struct instruction *instruction);

uint8_t process_elf(char *elfFile)
{
	Elf32_Ehdr header;
	FILE *file;
	Elf32_Shdr sh;
	uint8_t i, res;
	struct mappedBin *mf;
	uint32_t offset;

	file = fopen(elfFile, "rb");

	if (!file) {
		fprintf(stderr, "[-] Error while opening the file!\n");
		return EOPEN;
	}
	res = 0;

	// Read the ELF header
	if (!fread(&header, sizeof(header), 1, file)) {
		fprintf(stderr, "[-] Error while reading the ELF file!\n");
		res = EIO;
		goto close;
	}

	// Check so its really an elf file
	if (0 == (!memcmp(header.e_ident, ELFMAG, SELFMAG))) {
		fprintf(stderr, "[-] Not an ELF file!\n");
		res = ENOELF;
		goto close;
	}

	// Check the arch
	if (!checkArch(&header)) {
		fprintf(stderr, "[-] Bad architecture!\n");
		res = EBARCH;
		goto close;
	}

	// Check the bitness
	if (getBits(&header)) {
		if (CS_ERR_OK !=
		    cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle)) {
			fprintf(stderr,
				"[-] Error starting capstone engine!\n");
			goto close;
		}
		is64Bit = true;

	} else {
		if (CS_ERR_OK !=
		    cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32, &handle)) {
			fprintf(stderr,
				"[-] Error starting capstone engine!\n");
			goto close;
		}
		is64Bit = false;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	// Check if the program has any program header
	if (!header.e_phnum) {
		fprintf(stderr, "[-] Invalid ELF file!\n");
		res = EINVFILE;
		goto cclose;
	} else {
		mf = mapFile(file);
		if (NULL == mf) {
			goto cclose;
		}
		for (i = 0; i < header.e_shnum; i++) {
			offset = header.e_shoff + header.e_shentsize * i;
			fseek(file, offset, SEEK_SET);
			fread(&sh, sizeof(sh), 1, file);
			if ((SHT_PROGBITS == sh.sh_type) &&
			    ((SHF_ALLOC | SHF_EXECINSTR) == sh.sh_flags)) {
				if (1 == dumpCode(&sh, mf->address)) {
					res = EIINS;
					break;
				}
			}
		}
	}
	unmapFile(mf);

cclose:
	cs_close(&handle);
close:
	fclose(file);
	return res;
}

static int disas(unsigned char *opcode, uint64_t address)
{
	cs_insn *insn;
	size_t count;
	instruction *current;
	uint8_t last;

	count = cs_disasm(handle, opcode, sizeof(opcode) - 1, address, 0,
			  &insn);
	if (count > 0) {
		current = (struct instruction *)calloc(1, sizeof(instruction));
		if (is64Bit) {
			current->addr.addr64 = address;
		} else {
			current->addr.addr32 = (uint32_t)address;
		}
		cs_insn *i = &(insn[0]);
		current->disassembled = (const char *)calloc(
			strlen(i->mnemonic) + strlen(i->op_str) + 2,
			sizeof(char));
		strncpy((char *)current->disassembled, i->mnemonic,
			strlen(i->mnemonic));
		if (!strstr("ret", i->mnemonic)) {
			memset((void *)&current
				       ->disassembled[strlen(i->mnemonic)],
			       0x20, sizeof(char));
		}
		strncpy((char *)&current->disassembled[strlen(i->mnemonic) + 1],
			i->op_str, strlen(i->op_str));
		cs_detail *detail = insn->detail;
		last = fillData(current, detail);
		switch (args.mode) {
		case JOP_MODE:
			if ((JMP == current->operation) &&
			    strstr(current->disassembled, "jr")) {
				processGadgets(last, current->operation);
			}
			break;

		case SYSCALL_MODE:
			if (SYSCALL == current->operation) {
				processGadgets(last, current->operation);
			}
			break;

		case RET_MODE:
		default:
			if (RET == current->operation) {
				processGadgets(last, current->operation);
			}
			break;

		case GENERIC_MODE:
			if ((RET == current->operation) ||
			    (SYSCALL == current->operation) ||
			    ((JMP == current->operation) &&
			     strstr(current->disassembled, "jr"))) {
				processGadgets(last, current->operation);
			}
			break;
		}
		cs_free(insn, count);
	} else {
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
		return 1;
	}
	return 0;
}

static int dumpCode(Elf32_Shdr *sect, char *mappedBin)
{
	int32_t *opcode;
	uint64_t vaddr;
	uint32_t i;
	unsigned char *opcode_ptr =
		(unsigned char *)calloc(1, sizeof(char) * 5);

	opcode = (int *)(mappedBin + sect->sh_offset);
	vaddr = sect->sh_addr;

	list = create();
	spDuplicated = create();

	for (i = 0; i < sect->sh_size / 4; i++, vaddr += 4, opcode++) {
		getOpcode(*opcode, opcode_ptr);
		if (1 == disas(opcode_ptr, vaddr)) {
			free(opcode_ptr);
			return 1;
		}
	}
	printContent(list);
	return 0;
}

static uint8_t fillData(struct instruction *instruction, cs_detail *detail)
{
	char start = instruction->disassembled[0];
	cs_riscv_op *op;
	switch (start) {
	case 'l':
		if (!strstr(instruction->disassembled, ".w")) {
			instruction->operation = LOAD;
		}

		else {
			instruction->operation = ATOMIC;
		}
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'b':
		instruction->operation = CMP;
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'j':
	case 't':
		if (strstr(instruction->disassembled, "jal")) {
			instruction->operation = CALL;
		}

		else {
			instruction->operation = JMP;
		}

		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'o':
	case 'x':
		instruction->operation = OR;
		if (strstr(instruction->disassembled, "i")) {
			instruction->useImmediate = true;
		}

		else {
			instruction->useImmediate = false;
		}
		instruction->useShift = false;
		break;

	case 'e':
		if (strstr(instruction->disassembled, "ecall")) {
			instruction->operation = SYSCALL;
		}

		else {
			instruction->operation = BRK;
		}
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'r':
		if (!strstr(instruction->disassembled, "remu")) {
			instruction->operation = RET;
		}

		else {
			instruction->operation = MUL;
		}
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'n':
		if (strstr(instruction->disassembled, "t")) {
			instruction->operation = NOT;
		}

		else if (strstr(instruction->disassembled, "g")) {
			instruction->operation = NEG;
		}

		else {
			instruction->operation = NOP;
		}
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'm':
		if (!strstr(instruction->disassembled, "mul")) {
			instruction->operation = MOV;
		}

		else {
			instruction->operation = MUL;
		}
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 'a':
		if (!strstr(instruction->disassembled, ".w")) {
			if (strstr(instruction->disassembled, "ad") ||
			    strstr(instruction->disassembled, "au")) {
				instruction->operation = ADD;
			}

			else {
				instruction->operation = AND;
			}

			if (strstr(instruction->disassembled, "i")) {
				instruction->useImmediate = true;
			}

			else {
				instruction->useImmediate = false;
			}
		}

		else {
			instruction->operation = ATOMIC;
			instruction->useImmediate = false;
		}
		instruction->useShift = false;
		break;

	case 'f':
		instruction->operation = IO;
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	case 's':
		if (!strstr(instruction->disassembled, ".w")) {
			if (strstr(instruction->disassembled, "sub")) {
				instruction->operation = SUB;
				instruction->useImmediate = false;
				instruction->useShift = false;
			}

			else if (strstr(instruction->disassembled, "se") ||
				 strstr(instruction->disassembled, "slt") ||
				 strstr(instruction->disassembled, "sn") ||
				 strstr(instruction->disassembled, "sg")) {
				instruction->operation = SET;
				instruction->useShift = false;
				if (strstr(instruction->disassembled, "i")) {
					instruction->useImmediate = true;
				}

				else {
					instruction->useImmediate = false;
				}
			}

			else if (strstr(instruction->disassembled, "sr") ||
				 strstr(instruction->disassembled, "sll")) {
				instruction->operation = SHIFT;
				instruction->useShift = true;
				if (strstr(instruction->disassembled, "i")) {
					instruction->useImmediate = true;
				}

				else {
					instruction->useImmediate = false;
				}
			}

			else {
				instruction->operation = STORE;
				instruction->useImmediate = false;
				instruction->useShift = false;
			}
		}

		else {
			instruction->operation = ATOMIC;
			instruction->useImmediate = false;
			instruction->useShift = false;
		}
		break;

	case 'd':
		instruction->operation = DIV;
		instruction->useImmediate = false;
		instruction->useShift = false;
		break;

	default:
		instruction->operation = UNSUPORTED;
		break;
	}

	switch (detail->riscv.op_count) {
	case 1:
		op = &(detail->riscv.operands[0]);
		if (op->type == RISCV_OP_IMM) {
			instruction->immediate = op->imm;
		} else if (op->type == RISCV_OP_REG) {
			instruction->regDest = cs_reg_name(handle, op->reg);
		}
		break;

	case 2:
		op = &(detail->riscv.operands[0]);
		instruction->regDest = cs_reg_name(handle, op->reg);
		op = &(detail->riscv.operands[1]);
		if (op->type == RISCV_OP_IMM) {
			instruction->immediate = op->imm;
		}
		break;

	case 3:
		op = &(detail->riscv.operands[0]);
		instruction->regDest = cs_reg_name(handle, op->reg);
		if (instruction->useShift) {
			op = &(detail->riscv.operands[1]);
			instruction->regToShift = cs_reg_name(handle, op->reg);
		}
		op = &(detail->riscv.operands[2]);
		if (op->type == RISCV_OP_IMM) {
			instruction->immediate = op->imm;
		}
		break;
	}
	return pushToPGL(instruction);
}

static void getOpcode(int opcode, unsigned char *opcode_ptr)
{
	opcode_ptr[0] = 0xFF & opcode;
	opcode_ptr[1] = (0xFF00 & opcode) >> 8;
	opcode_ptr[2] = (0xFF0000 & opcode) >> 16;
	opcode_ptr[3] = (0xFF000000 & opcode) >> 24;
}

static struct mappedBin *mapFile(FILE *file)
{
	uint8_t fd;
	struct stat statbuf;
	struct mappedBin *res =
		(struct mappedBin *)malloc(sizeof(struct mappedBin));

	fd = fileno(file);
	if (fstat(fd, &statbuf)) {
		fprintf(stderr, "[-] Error while stating the file!\n");
		goto error;
	}
	res->size = statbuf.st_size;
	res->address =
		(char *)mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == res->address) {
		fprintf(stderr, "[-] Error mapping the file!\n");
		goto error;
	}

	return res;
error:
	return NULL;
}

static uint8_t pushToPGL(struct instruction *instruction)
{
	// Inserts new record in the list and return it's index
	static uint8_t pos = 0;
	preliminary_gadget_list[pos % 100] = instruction;
	return pos++ % 100;
}