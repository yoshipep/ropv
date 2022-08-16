#include <capstone/capstone.h>
#include <elf.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static csh handle;

void checkElf(const char *elfFile);

static void dumpCode(FILE *file, Elf32_Phdr *segm, Elf32_Ehdr *header);

static int disas(unsigned char *opcode, uint32_t address);

static void getOpcode(int opcode, unsigned char *opcode_ptr);

int main(void)
{
	// checkElf("/opt/rv32/sysroot/lib/libc.so.6");
	// checkElf("./files/test2");
	checkElf("./files/test1");
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
	return 2 == header->e_ident[EI_CLASS] ? true : false;
}

void checkElf(const char *elfFile)
{
	Elf32_Ehdr header;
	FILE *file;
	Elf32_Phdr program_header;
	uint8_t i;

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
	}

	for (i = 0; i < header.e_phnum; i++) {
		uint32_t offset = header.e_phoff + header.e_phentsize * i;
		fseek(file, offset, SEEK_SET);
		fread(&program_header, sizeof(program_header), 1, file);
		// Miramos si esta program header contiene instrucciones ejecutables
		if (((PF_X | PF_R) == program_header.p_flags)) {
			dumpCode(file, &program_header, &header);
		}
	}

close:
	fclose(file);
}

static void dumpCode(FILE *file, Elf32_Phdr *segm, Elf32_Ehdr *header)
{
	int32_t *opcode;
	uint32_t offset, vaddr, i;
	char *mappedFile;
	struct stat statbuf;
	int fd;
	unsigned char *opcode_ptr = (unsigned char *)malloc(sizeof(char) * 4);

	fd = fileno(file);
	if (fstat(fd, &statbuf)) {
		fprintf(stderr, "[-] Error while stating the file!\n");
		goto fail;
	}

	mappedFile =
		(char *)mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == mappedFile) {
		fprintf(stderr, "[-] Error mapping the file!\n");
		goto fail;
	}

	offset = segm->p_offset;
	opcode = (int *)(mappedFile + offset);
	vaddr = segm->p_vaddr;
	i = 0;

	/*Caso de que el segmento empiece en el offset 0*/
	if (0 == offset) {
		while (header->e_entry != vaddr) {
			i++;
			vaddr += 4;
			opcode++;
		}
	}

	for (; i < segm->p_filesz / 4; i++, vaddr += 4) {
		getOpcode(*opcode++, opcode_ptr);
		if (1 == disas(opcode_ptr, vaddr)) {
			free(opcode_ptr);
			break;
		}
	}

	cs_close(&handle);
	munmap(mappedFile, statbuf.st_size);

fail:
	close(fd);
}

static void getOpcode(int opcode, unsigned char *opcode_ptr)
{
	opcode_ptr[0] = 0xFF & opcode;
	opcode_ptr[1] = (0xFF00 & opcode) >> 8;
	opcode_ptr[2] = (0xFF0000 & opcode) >> 16;
	opcode_ptr[3] = (0xFF000000 & opcode) >> 24;
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
#ifdef DEBUG
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
#endif
		return 1;
	}
	return 0;
}
