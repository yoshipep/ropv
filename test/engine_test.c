#include <stdbool.h>
#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#define CODE "\x13\x05\x10\x00" // Little endian opcode

void checkElf(const char *elfFile);

void read_program_headers(const char *elfFile, Elf32_Ehdr *header, FILE *file);

void dumpCode(FILE *file, Elf32_Phdr *segm, Elf32_Ehdr *header);

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	checkElf("./test");

	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_RISCVC, &handle) !=
	    CS_ERR_OK) {
		return -1;
	}

	count = cs_disasm(handle, (uint8_t *)CODE, sizeof(CODE) - 1, 0x1000, 0,
			  &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
			       insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	return 0;
}

static bool checkArch(Elf32_Half arch)
{
	// Return true if the binary is from the RISC-V arch
	return arch == 243;
}

static bool getBits(Elf32_Ehdr *header)
{
	// If value equals to 2, the binary is from a 64 bits arch
	return (*header).e_ident[EI_CLASS] == 2 ? true : false;
}

void checkElf(const char *elfFile)
{
	Elf32_Ehdr header;
	FILE *file;

	file = fopen(elfFile, "rb");

	if (!file) {
		fprintf(stderr, "[-] Error while opening the file\n");
	}

	// Read the ELF header
	if (!fread(&header, sizeof(header), 1, file)) {
		fprintf(stderr, "[-] Error while reading the ELF file\n");
		goto close;
	}

	// Check so its really an elf file
	if ((!memcmp(header.e_ident, ELFMAG, SELFMAG)) == 0) {
		fprintf(stderr, "[-] Not an ELF file\n");
		goto close;
	}

	// Check the arch
	if (!checkArch(header.e_machine)) {
		fprintf(stderr, "[-] Bad architecture\n");
		goto close;
	}

	// Check the bitness
	if (getBits(&header)) {
		fprintf(stderr, "[-] Bitness not suported\n");
		goto close;
	}

	// Check if the program has any program header
	if (!header.e_phnum) {
		fprintf(stderr, "[-] Invalid ELF file\n");
		goto close;
	}

	read_program_headers(elfFile, &header, file);

close:
	fclose(file);
}

void read_program_headers(const char *elfFile, Elf32_Ehdr *header, FILE *file)
{
	Elf32_Phdr
		program_header; // Struct que representa la program header table
	for (uint i = 0; i < header->e_phnum; i++) {
		uint offset = header->e_phoff + header->e_phentsize * i;
		fseek(file, offset, SEEK_SET);
		fread(&program_header, sizeof(program_header), 1, file);
		// Miramos si esta program header tiene permisos de ejecución
		if (0x1 & program_header.p_flags) {
			dumpCode(file, &program_header, header);
			break;
		}
	}
}

void dumpCode(FILE *file, Elf32_Phdr *segm, Elf32_Ehdr *header)
{
	char *fileptr;
	struct stat statbuf;
	int *ptr;
	unsigned int i, addr;

	int fd = fileno(file);
	if (fstat(fd, &statbuf)) {
		fprintf(stderr, "[-] Error while stating the file!\n");
		close(fd);
	}

	fileptr =
		(char *)mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (MAP_FAILED == fileptr) {
		fprintf(stderr, "[-] Error mapping the file!\n");
		close(fd);
	}

	ptr = (int *)(fileptr +
		      (0 == segm->p_offset ?
			       sizeof(*header) +
				       header->e_phnum * header->e_phentsize :
			       segm->p_offset));
	printf("%p -> %p\n", fileptr, ptr);
	addr = (0 == segm->p_offset ?
			segm->p_vaddr + sizeof(*header) +
				header->e_phnum * header->e_phentsize :
			segm->p_vaddr);

	for (i = 0; i < segm->p_filesz / 4; i++, ptr++, addr += 4) {
		printf("Address: 0x%08x\n", addr);
		printf("Opcode: 0x%08x\n", *ptr);
	}

	munmap(fileptr, statbuf.st_size);
	close(fd);
}
