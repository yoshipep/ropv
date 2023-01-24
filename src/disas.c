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

static enum bits { BIT64 = 0, BIT32 = 1 } bitness;

static __attribute__((always_inline)) inline bool checkArch(Elf32_Ehdr *hdr);

static int disas(Elf32_Shdr *sect, char *mappedAddress, unsigned char *opcode);

static uint8_t fillData(struct instruction *ins, cs_detail *det,
			cs_insn *cs_inst);

static __attribute__((always_inline)) inline bool getBits(Elf32_Ehdr *hdr);

static void getOpcode(int opcode, unsigned char *opcode_ptr);

static uint8_t initializeCapstone(uint8_t usesCIns);

static inline bool isValidJump(enum riscv_insn *op);

static struct mappedFile *mapFile(FILE *f);

static uint8_t pushToPGL(struct instruction *ins);

static __attribute__((always_inline)) inline void
unmapFile(struct mappedFile *mf);

uint8_t process_elf(char *elfFile)
{
	Elf32_Ehdr hdr;
	FILE *f;
	Elf32_Shdr sh;
	uint8_t i, res;
	struct mappedFile *mf;
	uint32_t off;
	unsigned char *opcode = (unsigned char *)calloc(1, sizeof(char) * 5);
	f = fopen(elfFile, "rb");
	if (!f) {
		fprintf(stderr, "[-] Error while opening the file!\n");
		return EOPEN;
	}
	res = 0;
	// Read the ELF header
	if (!fread(&hdr, sizeof(hdr), 1, f)) {
		fprintf(stderr, "[-] Error while reading the ELF file!\n");
		res = EIO;
		goto file_close;
	}
	// Check so its really an elf file
	if (0 == (!memcmp(hdr.e_ident, ELFMAG, SELFMAG))) {
		fprintf(stderr, "[-] Not an ELF file!\n");
		res = ENOELF;
		goto file_close;
	}
	// Check the arch
	if (!checkArch(&hdr)) {
		fprintf(stderr, "[-] Bad architecture!\n");
		res = EBARCH;
		goto file_close;
	}
	// Check if the program has any program header
	if (!hdr.e_phnum) {
		fprintf(stderr, "[-] Invalid ELF file!\n");
		res = EINVFILE;
		goto file_close;
	} else {
		bitness = getBits(&hdr);
		initializeCapstone(hdr.e_flags);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		mf = mapFile(f);
		if (NULL == mf)
			goto capstone_close;
		for (i = 0; i < hdr.e_shnum; i++) {
			off = hdr.e_shoff + hdr.e_shentsize * i;
			fseek(f, off, SEEK_SET);
#pragma clang diagnostic ignored "-Wunused-result"
			fread(&sh, sizeof(sh), 1, f);
			if ((SHT_PROGBITS == sh.sh_type) &&
			    ((SHF_ALLOC | SHF_EXECINSTR) == sh.sh_flags) &&
			    (1 == disas(&sh, mf->address, opcode))) {
				res = EIINS;
				break;
			}
		}
		free(opcode);
		opcode = NULL;
		printContent(list);
	}
	unmapFile(mf);
capstone_close:
	cs_close(&handle);
file_close:
	fclose(f);
	return res;
}

static inline bool checkArch(Elf32_Ehdr *hdr)
{
	// Return true if the binary is from the RISC-V arch
	return 243 == hdr->e_machine;
}

static int disas(Elf32_Shdr *sect, char *mappedAddress, unsigned char *opcode)
{
	cs_insn *insn;
	size_t count;
	uint32_t i;
	uint64_t vaddr;
	int32_t *opcode_ptr;
	struct instruction *current;
	uint8_t last;
	if (NULL == list)
		list = create();

	if (NULL == spDuplicated)
		spDuplicated = create();
	opcode_ptr = (int *)(mappedAddress + sect->sh_offset);
	vaddr = sect->sh_addr;
	for (i = 0; i < sect->sh_size / 4; i++) {
		getOpcode(*opcode_ptr, opcode);
		// Here is obtained the current instruction
		count = cs_disasm(handle, opcode, sizeof(opcode) - 1, vaddr, 0,
				  &insn);
		if (count > 0) {
			current = (struct instruction *)calloc(
				1, sizeof(struct instruction));
			if (BIT64 == bitness)
				current->addr.addr64 = vaddr;
			else
				current->addr.addr32 = (uint32_t)vaddr;
			last = fillData(current, insn->detail, &(insn[0]));
			switch (args.mode) {
			case JOP_MODE:
				if (isValidJump(&current->operation))
					processGadgets(last,
						       current->operation);
				break;
			case SYSCALL_MODE:
				if (RISCV_INS_ECALL == current->operation)
					processGadgets(last,
						       current->operation);
				break;
			case RET_MODE:
			default:
				if ('r' == current->disassembled[0])
					processGadgets(last, 0);
				break;
			case GENERIC_MODE:
				if ('r' == current->disassembled[0])
					processGadgets(last, 0);
				if ((RISCV_INS_ECALL == current->operation) ||
				    (isValidJump(&current->operation)))
					processGadgets(last,
						       current->operation);
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
				"ERROR: Failed to disassemble the given code!\n Address: 0x%08x\n",
				vaddr);
			return 1;
		}
	}
	return 0;
}

static uint8_t fillData(struct instruction *ins, cs_detail *det,
			cs_insn *cs_inst)
{
	cs_riscv_op *op;
	ins->disassembled = (const char *)calloc(
		strlen(cs_inst->mnemonic) + strlen(cs_inst->op_str) + 2,
		sizeof(char));
	strncpy((char *)ins->disassembled, cs_inst->mnemonic,
		strlen(cs_inst->mnemonic));
	if (!strstr("ret", cs_inst->mnemonic) && RISCV_INS_ECALL != cs_inst->id)
		// Here a space is set between the mnemonic and the op str
		memset((void *)&ins->disassembled[strlen(cs_inst->mnemonic)],
		       0x20, sizeof(char));
	strncpy((char *)&ins->disassembled[strlen(cs_inst->mnemonic) + 1],
		cs_inst->op_str, strlen(cs_inst->op_str));
	ins->operation = cs_inst->id;
	ins->useImmediate = false;
	op = &(det->riscv.operands[0]);
	switch (det->riscv.op_count) {
	case 1:
		if (RISCV_OP_IMM == op->type) {
			ins->immediate = op->imm;
		} else if (op->type == RISCV_OP_REG) {
			ins->regDest = cs_reg_name(handle, op->reg);
		}
		break;
	case 2:
		ins->regDest = cs_reg_name(handle, op->reg);
		op = &(det->riscv.operands[1]);
		if (RISCV_OP_IMM == op->type) {
			ins->immediate = op->imm;
			ins->useImmediate = true;
		}
		break;
	case 3:
		ins->regDest = cs_reg_name(handle, op->reg);
		op = &(det->riscv.operands[2]);
		if (RISCV_OP_IMM == op->type) {
			ins->immediate = op->imm;
			ins->useImmediate = true;
		}
		break;
	}
	return pushToPGL(ins);
}

static inline bool getBits(Elf32_Ehdr *hdr)
{
	// If value equals to 2, the binary is from a 64 bits arch
	return 2 == hdr->e_ident[EI_CLASS];
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
	if (0 != res)
		fprintf(stderr, "[-] Error starting capstone engine!\n");
	return res;
}

static inline bool isValidJump(enum riscv_insn *op)
{
	return (RISCV_INS_C_JALR == *op) || (RISCV_INS_JALR == *op);
}

static struct mappedFile *mapFile(FILE *f)
{
	uint8_t fd;
	struct stat statbuf;
	struct mappedFile *res =
		(struct mappedFile *)malloc(sizeof(struct mappedFile));
	fd = fileno(f);
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

static uint8_t pushToPGL(struct instruction *ins)
{
	// Inserts new record in the list and return it's index
	static uint8_t pos = 0;
	preliminary_gadget_list[pos % 100] = ins;
	return pos++ % 100;
}

static inline void unmapFile(struct mappedFile *mf)
{
	munmap(mf->address, mf->size);
}