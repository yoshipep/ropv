#include <capstone/capstone.h>
#include <elf.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static csh handle;

struct mappedBin {
	char *address;
	off_t size;
};

void checkElf(const char *elfFile);

static int disas(Elf32_Shdr *sect, char *mappedBin,
		 unsigned char *opcode_content);

static inline void getOpcode(int opcode_ptr, unsigned char *opcode_content);

static struct mappedBin *mapFile(FILE *file);

static __attribute__((always_inline)) inline void
unmapFile(struct mappedBin *file);

int main(void)
{
	checkElf("./files/test1");
	// checkElf("./files/test2");
	// checkElf("./files/test3");
	// checkElf("/opt/rv32/sysroot/lib/libc.so.6");
	return 0;
}

static bool checkArch(Elf32_Ehdr *header)
{
	// Return true if the binary is from the RISC-V arch
	return 243 == header->e_machine;
}

static bool getBits(Elf32_Ehdr *header)
{
	// If value equals to 2, the binary is from a 64 bits arch
	return 2 == header->e_ident[EI_CLASS];
}

void checkElf(const char *elfFile)
{
	Elf32_Ehdr header;
	FILE *file;
	Elf32_Shdr sh;
	uint8_t i;
	struct mappedBin *mf;
	uint32_t offset;
	unsigned char *opcode_content =
		(unsigned char *)calloc(1, sizeof(char) * 5);

	file = fopen(elfFile, "rb");

	if (!file) {
		fprintf(stderr, "[-] Error while opening the file!\n");
		return;
	}

	// Read the ELF header
	if (!fread(&header, sizeof(header), 1, file)) {
		fprintf(stderr, "[-] Error while reading the ELF file!\n");
		goto close;
	}

	// Check so its really an elf file
	if (0 == (!memcmp(header.e_ident, ELFMAG, SELFMAG))) {
		fprintf(stderr, "[-] Not an ELF file!\n");
		goto close;
	}

	// Check the arch
	if (!checkArch(&header)) {
		fprintf(stderr, "[-] Bad architecture!\n");
		goto close;
	}

	// Check the bitness
	if (getBits(&header)) {
		if (CS_ERR_OK != cs_open(CS_ARCH_RISCV,
					 CS_MODE_RISCV64 + CS_MODE_RISCVC,
					 &handle)) {
			fprintf(stderr,
				"[-] Error starting capstone engine!\n");
			goto close;
		}

	} else {
		if (CS_ERR_OK != cs_open(CS_ARCH_RISCV,
					 CS_MODE_RISCV32 + CS_MODE_RISCVC,
					 &handle)) {
			fprintf(stderr,
				"[-] Error starting capstone engine!\n");
			goto close;
		}
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	// Check if the file has any program header
	if (!header.e_phnum) {
		fprintf(stderr, "[-] Invalid ELF file!\n");
		goto close;
	} else {
		mf = mapFile(file);
		if (NULL == mf) {
			goto close;
		}
		for (i = 0; i < header.e_shnum; i++) {
			offset = header.e_shoff + header.e_shentsize * i;
			fseek(file, offset, SEEK_SET);
			fread(&sh, sizeof(sh), 1, file);
			if ((SHT_PROGBITS == sh.sh_type) &&
			    ((SHF_ALLOC | SHF_EXECINSTR) == sh.sh_flags)) {
				disas(&sh, mf->address, opcode_content);
			}
		}
		free(opcode_content);
		opcode_content = NULL;
	}
	unmapFile(mf);

close:
	fclose(file);
	cs_close(&handle);
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

static inline void unmapFile(struct mappedBin *file)
{
	munmap(file->address, file->size);
}

static inline void getOpcode(int opcode_ptr, unsigned char *opcode_content)
{
	opcode_content[0] = 0xFF & opcode_ptr;
	opcode_content[1] = ((0xFF << 8) & opcode_ptr) >> 8;
	opcode_content[2] = ((0xFF << 16) & opcode_ptr) >> 16;
	opcode_content[3] = ((0xFF << 24) & opcode_ptr) >> 24;
}

static int disas(Elf32_Shdr *sect, char *mappedBin,
		 unsigned char *opcode_content)
{
	cs_insn *insn;
	size_t count;
	uint32_t vaddr, i;
	int32_t *opcode_ptr;

	opcode_ptr = (int *)(mappedBin + sect->sh_offset);
	vaddr = sect->sh_addr;

	for (i = 0; i < sect->sh_size / 4; i++) {
		getOpcode(*opcode_ptr, opcode_content);
		count = cs_disasm(handle, opcode_content,
				  sizeof(opcode_content) - 1, vaddr, 0, &insn);

		if (count > 0) {
			cs_insn *i = &(insn[0]);
			printf("Count: %d\t0x%" PRIx64
			       ":%c%s%c%s // insn-mnem: %s \t id: %d\n",
			       i->detail->riscv.op_count, i->address, 0x20,
			       i->mnemonic, 0x20, i->op_str,
			       cs_insn_name(handle, i->id), i->id);
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
