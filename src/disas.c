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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "datatypes.h"
#include "disas.h"

static inline uint8_t checkArch(Elf32_Half arch);

static inline uint8_t getBits(Elf32_Ehdr *header);

static uint8_t process_elf(const char *elfFile);

static uint8_t disassemble(const char *elfFile);

static uint8_t parseContent(const char *assemblyFile);

static void fillData(struct ins32_t *instruction);

static void setInmediate(struct ins32_t *instruction);

static void setShift(struct ins32_t *instruction);

static inline uint8_t checkArch(Elf32_Half arch)
{
    return arch == 243;
}

static inline uint8_t getBits(Elf32_Ehdr *header)
{
    /*Si el valor es 2, indica que es un ejecutable de 64 bits*/
    return (*header).e_ident[EI_CLASS] != 2 ? 1 : 0;
}

static uint8_t process_elf(const char *elfFile)
{
    Elf32_Ehdr header;
    FILE *file;
    uint8_t res = 1;
    if (verbose)
    {
        puts("[+] Opening the file");
    }

    file = fopen(elfFile, "rb");
    if (file)
    {
        // read the header
        if (fread(&header, sizeof(header), 1, file))
        {

            // check so its really an elf file
            if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0)
            {
                if (verbose)
                {
                    puts("[+] Checking architecture");
                }
                if (checkArch(header.e_machine))
                {
                    if (verbose)
                    {
                        puts("[+] Checking bitness");
                    }
                    if (getBits(&header))
                    {
                        res = 0;
                    }
                    else
                    {
                        fprintf(stderr, "[-] Bitness not suported\n");
                    }
                }
                else
                {
                    fprintf(stderr, "[-] Bad architecture\n");
                }
            }
            else
            {
                fprintf(stderr, "[-] Not an ELF file\n");
            }
        }
        else
        {
            fprintf(stderr, "[-] Error while reading the ELF file\n");
        }
        fclose(file);
    }
    return res;
}

static uint8_t disassemble(const char *elfFile)
{
    pid_t child;
    int returnStatus;
    int fd, tempfd;

    char *args[] = {"/opt/rv32/bin/riscv32-unknown-linux-gnu-objdump", "-d", (void *)elfFile, NULL};

    if (verbose)
    {
        puts("[+] Creating dummy file");
    }

    fd = open(DUMMY_FILE, O_WRONLY | O_CREAT, DEFAULT_PERM);
    if (fd)
    {
        tempfd = open("/dev/null", O_WRONLY);
        if (!tempfd)
        {
            fprintf(stderr, "[-] Unable to open /dev/null\n");
        }

        if (process_elf(elfFile))
        {
            goto fail;
        }

        if (verbose)
        {
            puts("[+] Dissasembling the binary");
        }
        child = fork();

        if (!child)
        {
            dup2(fd, STDOUT_FILENO);
            dup2(tempfd, STDERR_FILENO);
            close(fd);
            close(tempfd);
            execve(args[0], args, NULL);
        }

        close(fd);
        close(tempfd);
        waitpid(child, &returnStatus, 0);

        if (returnStatus)
        {
            fprintf(stderr, "[-] Program failed\n");
            goto fail;
        }

        return parseContent(DUMMY_FILE);
    }
    else
    {
        fprintf(stderr, "[-] Unable to create a dummy file\n");
        goto fail;
    }
fail:
    return 1;
}

static uint8_t parseContent(const char *assemblyFile)
{

    FILE *file;
    size_t len = 0;
    ssize_t read = -1;
    char *line;
    char *address;
    char *pos;
    uint8_t start = 0;
    uint8_t nIns;
    int32_t baseAddress;
    size_t endPos;
    size_t startPos;
    uint8_t nTabs;

    if (verbose)
    {
        puts("[+] Opening dummy file");
    }

    file = fopen(assemblyFile, "r");

    if (!file)
    {
        fprintf(stderr, "[-] Unable to open the dummy file\n");
        return 1;
    }
    // unlink(assemblyFile);

    if (verbose)
    {
        puts("[+] Parsing the content");
    }
    do
    {
        read = getline(&line, &len, file) != -1;
        if (!read)
        {
            break;
        }

        // Check if the line is the start of a function
        if (!start && line[strlen(line) - 2] == ':' && (line[0] - '0' >= 0 && line[0] - '0' <= 9) && !strstr(line, "_PROCEDURE_LINKAGE_TABLE_"))
        {
            start = 1;
            address = malloc(sizeof(char) * 8);
            address = strncpy(address, line, 8);
            baseAddress = strtol(address, NULL, 0x10);
            free(address);
            address = NULL;
            nIns = 0;
            continue;
        }

        if (start)
        {
            startPos = 0;
            nTabs = 0;
            if (line[0] == 0xa || strstr(line, "...") || strstr(line, "unimp"))
            {
                start = 0;
                continue;
            }

            pos = strstr(line, "#");

            if (!pos)
            {
                pos = strstr(line, "\n");
                endPos = pos - line;
            }
            else
            {
                endPos = pos - line - 1;
            }

            while (line[startPos] && nTabs < 2)
            {
                startPos++;
                if (line[startPos] == 0x9)
                {
                    nTabs++;
                }
            }

            startPos += 1;
            ins32_t current;
            current.address = baseAddress + nIns;
            current.disassembled = (char *)malloc(sizeof(char) * (endPos - startPos));
            strncpy(current.disassembled, &line[startPos], endPos - startPos);

            fillData(&current);

            nIns += 4;
            printf("0x%08x: \t%s\t%d\n", current.address, current.disassembled, current.mode);
            if (current.useImmediate)
            {
                printf("%hd\n", current.immediate);
            }
        }

    } while (read);

    return 0;
}

static void fillData(struct ins32_t *instruction)
{
    /*TODO: Registro a shiftear*/
    char start = instruction->disassembled[0];

    switch (start)
    {
    case 'l':
        instruction->operation = LOAD;
        instruction->mode = 0b0011;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;
    case 'b':
        instruction->operation = CMP;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;
    case 'j':
        instruction->operation = JMP;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;
    case 'x':
        instruction->operation = XOR;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
        }
        else
        {
            instruction->useImmediate = 0;
        }
        break;
    case 'o':
        instruction->operation = OR;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
        }
        else
        {
            instruction->useImmediate = 0;
        }
        break;
    case 'e':
        if (strstr(instruction->disassembled, "ecall"))
        {
            instruction->operation = CALL;
        }
        else
        {
            instruction->operation = BRK;
        }
        instruction->useShift = 0;
        instruction->useImmediate = 0;
        instruction->mode = 0;
        break;
    case 'n':
        instruction->operation = NOP;
        instruction->useShift = 0;
        instruction->useImmediate = 0;
        instruction->mode = 0;
        break;
    case 'm':
        instruction->operation = MOV;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        instruction->useImmediate = 0;
        break;
    case 'a':
        if (strstr(instruction->disassembled, "ad") || strstr(instruction->disassembled, "au"))
        {
            instruction->operation = ADD;
            instruction->mode = 0b0011;
        }
        else
        {
            instruction->operation = AND;
            instruction->mode = 0b0011;
        }
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
        }
        else
        {
            instruction->useImmediate = 0;
        }
        instruction->useShift = 0;
        break;
    case 's':
        if (strstr(instruction->disassembled, "sub"))
        {
            instruction->operation = SUB;
            instruction->mode = 0b0011;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
        }
        else if (strstr(instruction->disassembled, "slt") || strstr(instruction->disassembled, "sn") || strstr(instruction->disassembled, "sg"))
        {
            instruction->operation = SET;
            instruction->mode = 0b0011;
            instruction->useShift = 0;
            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = 1;
            }
            else
            {
                instruction->useImmediate = 0;
            }
        }
        else if (strstr(instruction->disassembled, "sr") || strstr(instruction->disassembled, "sll"))
        {
            instruction->operation = SHIFT;
            instruction->mode = 0b0011;
            instruction->useShift = 1;
            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = 1;
            }
            else
            {
                instruction->useImmediate = 0;
            }
            setShift(instruction);
        }
        else
        {
            instruction->operation = STORE;
            instruction->mode = 0b1100;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
        }
        break;
    default:
        break;
    }
    if (instruction->useImmediate)
    {
        setInmediate(instruction);
    }
}

static void setInmediate(struct ins32_t *instruction)
{
    char *isPresent = strstr(instruction->disassembled, "0x");
    char *dummy;
    size_t size;
    size_t startPos = strlen(instruction->disassembled) - 1;

    if (isPresent)
    {
        size = startPos - (&instruction->disassembled[startPos] - isPresent);
        dummy = (char *)malloc(sizeof(char) * size);

        strncpy(dummy, &instruction->disassembled[size + 2], size);
        instruction->immediate = atoi(dummy);
        goto liberate;
    }
    else
    {
        while (instruction->disassembled[startPos - 1] != ',')
        {
            startPos--;
        }
        dummy = (char *)malloc(sizeof(char) * (strlen(instruction->disassembled) - startPos));
        strncpy(dummy, &instruction->disassembled[startPos], startPos);
        instruction->immediate = atoi(dummy);
        goto liberate;
    }
    return;
liberate:
    free(dummy);
    dummy = NULL;
}

static void setShift(struct ins32_t *instruction)
{
    /*srli - slli - sll - srl - sra - srai*/
    if (strstr(instruction->disassembled, "srli"))
    {
        instruction->type = SRLI;
    }
    else if ((strstr(instruction->disassembled, "slli")))
    {
        instruction->type = SLLI;
    }
    else if ((strstr(instruction->disassembled, "sll")))
    {
        instruction->type = SLL;
    }
    else if ((strstr(instruction->disassembled, "srl")))
    {
        instruction->type = SRL;
    }
    else if ((strstr(instruction->disassembled, "sra")))
    {
        instruction->type = SRA;
    }
    else
    {
        instruction->type = SRAI;
    }
}
