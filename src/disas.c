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

static enum bits { BIT32, BIT64 } bitness;

static __attribute__((always_inline)) inline bool checkArch(Elf32_Ehdr *header);

static int disas(Elf32_Shdr *sect, char *mappedAddress,
		 unsigned char *opcode_content);

static uint8_t fillData(struct instruction *instruction, cs_detail *detail);

static __attribute__((always_inline)) inline bool getBits(Elf32_Ehdr *header);

static void getOpcode(int opcode, unsigned char *opcode_ptr);

static uint8_t initializeCapstone(uint8_t usesCIns);

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
	unsigned char *opcode_content =
		(unsigned char *)calloc(1, sizeof(char) * 5);

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

	// Check if the program has any program header
	if (!header.e_phnum) {
		fprintf(stderr, "[-] Invalid ELF file!\n");
		res = EINVFILE;
		goto close;
	} else {
		bitness = true == getBits(&header) ? BIT64 : BIT32;
		initializeCapstone(header.e_flags);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		mf = mapFile(file);
		if (NULL == mf) {
			goto cclose;
		}
		for (i = 0; i < header.e_shnum; i++) {
			offset = header.e_shoff + header.e_shentsize * i;
			fseek(file, offset, SEEK_SET);
#pragma clang diagnostic ignored "-Wunused-result"
			fread(&sh, sizeof(sh), 1, file);
			if ((SHT_PROGBITS == sh.sh_type) &&
			    ((SHF_ALLOC | SHF_EXECINSTR) == sh.sh_flags)) {
				if (1 ==
				    disas(&sh, mf->address, opcode_content)) {
					res = EIINS;
					break;
				}
			}
		}
		free(opcode_content);
		opcode_content = NULL;
		printContent(list);
	}
	unmapFile(mf);

cclose:
	cs_close(&handle);
close:
	fclose(file);
	return res;
}

static inline bool checkArch(Elf32_Ehdr *header)
{
	// Return true if the binary is from the RISC-V arch
	return 243 == header->e_machine;
}

static int disas(Elf32_Shdr *sect, char *mappedAddress,
		 unsigned char *opcode_content)
{
	cs_insn *insn;
	size_t count;
	uint32_t i;
	uint64_t vaddr;
	int32_t *opcode_ptr;
	instruction *current;
	uint8_t last;

	if (NULL == list) {
		list = create();
	}

	if (NULL == spDuplicated) {
		spDuplicated = create();
	}

	opcode_ptr = (int *)(mappedAddress + sect->sh_offset);
	vaddr = sect->sh_addr;

	for (i = 0; i < sect->sh_size / 4; i++) {
		getOpcode(*opcode_ptr, opcode_content);
		// Here is obtained the current instruction
		count = cs_disasm(handle, opcode_content,
				  sizeof(opcode_content) - 1, vaddr, 0, &insn);

		if (count > 0) {
			current = (struct instruction *)calloc(
				1, sizeof(instruction));
			if (BIT64 == bitness) {
				current->addr.addr64 = vaddr;
			} else {
				current->addr.addr32 = (uint32_t)vaddr;
			}
			cs_insn *i = &(insn[0]);
			current->disassembled = (const char *)calloc(
				strlen(i->mnemonic) + strlen(i->op_str) + 2,
				sizeof(char));
			strncpy((char *)current->disassembled, i->mnemonic,
				strlen(i->mnemonic));
			if (!strstr("ret", i->mnemonic) &&
			    !strstr("ecall", i->mnemonic)) {
				// Here a space is set between the mnemonic and the op str
				memset((void *)&current->disassembled[strlen(
					       i->mnemonic)],
				       0x20, sizeof(char));
			}
			strncpy((char *)&current
					->disassembled[strlen(i->mnemonic) + 1],
				i->op_str, strlen(i->op_str));
			cs_detail *detail = insn->detail;
			last = fillData(current, detail);
			switch (args.mode) {
			case JOP_MODE:
				if ((JMP == current->operation) &&
				    strstr(current->disassembled, "jr")) {
					processGadgets(last,
						       current->operation);
				}
				break;

			case SYSCALL_MODE:
				if (SYSCALL == current->operation) {
					processGadgets(last,
						       current->operation);
				}
				break;

			case RET_MODE:
			default:
				if (RET == current->operation) {
					processGadgets(last,
						       current->operation);
				}
				break;

			case GENERIC_MODE:
				if ((RET == current->operation) ||
				    (SYSCALL == current->operation) ||
				    ((JMP == current->operation) &&
				     strstr(current->disassembled, "jr"))) {
					processGadgets(last,
						       current->operation);
				}
				break;
			}
			cs_free(insn, count);
			if (2 == insn->size) {
				vaddr += 2;
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
				opcode_ptr = ((unsigned char *)opcode_ptr) + 2;
			} else {
				vaddr += 4;
				opcode_ptr++;
			}
		} else {
			fprintf(stderr,
				"ERROR: Failed to disassemble given code!\n");
			return 1;
		}
	}
	return 0;
}

static uint8_t fillData(struct instruction *instruction, cs_detail *detail)
{
	cs_riscv_op *op;
	char start = instruction->disassembled[0];
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

static inline bool getBits(Elf32_Ehdr *header)
{
	// If value equals to 2, the binary is from a 64 bits arch
	return 2 == header->e_ident[EI_CLASS];
}

static void getOpcode(int opcode, unsigned char *opcode_ptr)
{
	opcode_ptr[0] = 0xFF & opcode;
	opcode_ptr[1] = ((0xFF << 8) & opcode) >> 8;
	opcode_ptr[2] = ((0xFF << 16) & opcode) >> 16;
	opcode_ptr[3] = ((0xFF << 24) & opcode) >> 24;
}

static uint8_t initializeCapstone(uint8_t usesCIns)
{
	uint8_t res;
	if ((BIT64 == bitness) && usesCIns) {
		res = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_RISCVC,
			      &handle);
	} else if (!usesCIns) {
		res = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle);
	}

	if (!(BIT64 == bitness) && usesCIns) {
		res = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_RISCVC,
			      &handle);
	} else if (!usesCIns) {
		res = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32, &handle);
	}

	if (0 != res) {
		fprintf(stderr, "[-] Error starting capstone engine!\n");
	}

	return res;
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
	free(res);
	res = NULL;
	return NULL;
}

static uint8_t pushToPGL(struct instruction *instruction)
{
	// Inserts new record in the list and return it's index
	static uint8_t pos = 0;
	preliminary_gadget_list[pos % 100] = instruction;
	return pos++ % 100;
}