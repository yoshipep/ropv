#include <capstone/capstone.h>
#include <elf.h>
#include <inttypes.h>
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

struct mappedFile {
	char *address;
	off_t size;
};

void checkElf(const char *elfFile);

static void dumpCode(Elf32_Shdr *sect, char *mappedFile);

static int disas(unsigned char *opcode, uint32_t address);

static void getOpcode(int opcode, unsigned char *opcode_ptr);

static struct mappedFile *mapFile(FILE *file);

static __attribute__((always_inline)) inline void
unmapFile(struct mappedFile *file);

int main(void)
{
	checkElf("/opt/rv32/sysroot/lib/libc.so.6");
	// checkElf("./files/test2");
	// checkElf("./files/test1");
	// checkElf("./files/test3");
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
	struct mappedFile *mf;
	uint32_t offset;

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
		if (CS_ERR_OK !=
		    cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle)) {
			fprintf(stderr,
				"[-] Error starting capstone engine!\n");
			goto close;
		}

	} else {
		if (CS_ERR_OK !=
		    cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32, &handle)) {
			fprintf(stderr,
				"[-] Error starting capstone engine!\n");
			goto close;
		}
	}

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
				dumpCode(&sh, mf->address);
			}
		}
	}
	unmapFile(mf);

close:
	fclose(file);
	cs_close(&handle);
}

static struct mappedFile *mapFile(FILE *file)
{
	uint8_t fd;
	struct stat statbuf;
	struct mappedFile *res =
		(struct mappedFile *)calloc(1, sizeof(struct mappedFile));

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

static inline void unmapFile(struct mappedFile *file)
{
	munmap(file->address, file->size);
}

static void dumpCode(Elf32_Shdr *sect, char *mappedFile)
{
	int32_t *opcode;
	uint32_t vaddr, i;
	unsigned char *opcode_ptr = (unsigned char *)malloc(sizeof(char) * 5);

	opcode = (int *)(mappedFile + sect->sh_offset);
	vaddr = sect->sh_addr;
	i = 0;

	for (; i < sect->sh_size / 4; i++, vaddr += 4, opcode++) {
		getOpcode(*opcode, opcode_ptr);
		if (1 == disas(opcode_ptr, vaddr)) {
			free(opcode_ptr);
			break;
		}
	}
}

static void getOpcode(int opcode, unsigned char *opcode_ptr)
{
	opcode_ptr[0] = 0xFF & opcode;
	opcode_ptr[1] = (0xFF00 & opcode) >> 8;
	opcode_ptr[2] = (0xFF0000 & opcode) >> 16;
	opcode_ptr[3] = (0xFF000000 & opcode) >> 24;
	opcode_ptr[4] = 0x0;
}

static int disas(unsigned char *opcode, uint32_t address)
{
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, opcode, sizeof(opcode) - 1, address, 0,
			  &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
			       insn[j].mnemonic, insn[j].op_str);
		}
		cs_free(insn, count);
	} else {
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
		return 1;
	}
	return 0;
}
