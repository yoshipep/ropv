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

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "datatypes.h"
#include "errors.h"
#include "disas.h"
#include "gadgets.h"

#define DEFAULT_PERM 0644
#define DUMMY_FILE "/tmp/disas.s"

ins32_t *preliminary_gadget_list[100];

static void setInmediate(struct ins32_t *instruction);

static void setShift(struct ins32_t *instruction);

static uint8_t process_elf(char *elfFile);

static uint8_t parseContent(char *assemblyFile);

static __attribute__((always_inline)) inline uint8_t checkArch(Elf32_Half arch);

static __attribute__((always_inline)) inline uint8_t getBits(Elf32_Ehdr *header);

static __attribute__((always_inline)) inline uint8_t pushToPGL(struct ins32_t *instruction);

static __attribute__((always_inline)) inline uint8_t pushToPGL(struct ins32_t *instruction)
{
    static uint8_t pos = 0;
    preliminary_gadget_list[pos % 100] = instruction;
    return pos++ % 100;
}

static __attribute__((always_inline)) inline uint8_t checkArch(Elf32_Half arch)
{
    return arch == 243;
}

static __attribute__((always_inline)) inline uint8_t getBits(Elf32_Ehdr *header)
{
    /*If value equals to 2, the binary is from a 64 bits arch*/
    return (*header).e_ident[EI_CLASS] == 2 ? EBARCH : 0;
}

static uint8_t process_elf(char *elfFile)
{
    Elf32_Ehdr header;
    FILE *file;
    uint8_t res;

    file = fopen(elfFile, "rb");

    if (!file)
    {
        fprintf(stderr, "[-] Error while opening the file\n");
        return EOPEN;
    }
    res = 0;

    if (!fread(&header, sizeof(header), 1, file))
    {
        fprintf(stderr, "[-] Error while reading the ELF file\n");
        res = EIO;
        goto close;
    }

    // check so its really an elf file
    if (!memcmp(header.e_ident, ELFMAG, SELFMAG) == 0)
    {
        fprintf(stderr, "[-] Not an ELF file\n");
        res = EIFILE;
        goto close;
    }
    if (!checkArch(header.e_machine))
    {
        fprintf(stderr, "[-] Bad architecture\n");
        res = EBARCH;
        goto close;
    }

    if (getBits(&header))
    {
        fprintf(stderr, "[-] Bitness not suported\n");
        res = EBIT;
        goto close;
    }

    if (!header.e_phnum)
    {
        fprintf(stderr, "[-] Invalid ELF file\n");
        res = EIFILE;
        goto close;
    }

close:
    fclose(file);
    return res;
}

uint8_t disassemble(char *elfFile)
{
    pid_t child;
    int returnStatus, fd, tempfd;
    uint8_t res;

    char *args[] = {"/opt/rv32/bin/riscv32-unknown-linux-gnu-objdump", "-d", elfFile, NULL};

    fd = open(DUMMY_FILE, O_WRONLY | O_CREAT, DEFAULT_PERM);
    if (!fd)
    {
        fprintf(stderr, "[-] Unable to create a dummy file\n");
        return ECREAT;
    }
    tempfd = open("/dev/null", O_WRONLY);
    if (!tempfd)
    {
        fprintf(stderr, "[-] Unable to open /dev/null\n");
        res = EOPEN;
        goto fail;
    }

    if (process_elf(elfFile))
    {
        goto fail;
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
        res = ECHILD;
        goto fail;
    }

    return parseContent(DUMMY_FILE);

fail:
    if (fcntl(fd, F_GETFD))
    {
        close(fd);
    }

    if (fcntl(tempfd, F_GETFD))
    {
        close(tempfd);
    }
    return res;
}

static uint8_t parseContent(char *assemblyFile)
{

    FILE *file;
    char *line, *address, *pos, *opcode;
    uint8_t nIns, nTabs, last, bytes;
    int32_t baseAddress, endPos;
    size_t startPos;
    uint8_t start = 0;
    size_t len = 0;
    ssize_t read = -1;

    file = fopen(assemblyFile, "r");

    if (!file)
    {
        fprintf(stderr, "[-] Unable to open the dummy file\n");
        return EOPEN;
    }
    // unlink(assemblyFile);

    do
    {
        read = getline(&line, &len, file) != -1;
        if (!read)
        {
            break;
        }

        // Check if the line is the start of a function
        if (!start && ':' == line[strlen(line) - 2] && (line[0] - '0' >= 0 && line[0] - '0' <= 9) &&
            !strstr(line, "_PROCEDURE_LINKAGE_TABLE_"))
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
            if (0xa == line[0] || strstr(line, "...") || strstr(line, "unimp"))
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
                if (0x9 == line[startPos]) // Tab
                {
                    nTabs++;
                }
            }

            bytes = 0;
            startPos += 1;
            ins32_t *current = (ins32_t *)malloc(sizeof(ins32_t));
            memset(current, 0x0, sizeof(ins32_t));
            current->address = baseAddress + nIns;
            current->disassembled = (char *)malloc(sizeof(char) * (endPos - startPos));
            strncpy(current->disassembled, &line[startPos], endPos - startPos);

            last = fillData(current);

            if (RET == current->operation)
            {
                start = 0;
                processGadgets(last);
            }

            opcode = strstr(line, "\t") + 1;
            while (0x20 != *opcode++)
            {
                bytes++;
            }

            nIns += bytes / 2;
        }

    } while (read);

    return 0;
}

uint8_t fillData(struct ins32_t *instruction)
{
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
    case 't':
        instruction->operation = JMP;
        instruction->useImmediate = 0;
        instruction->useShift = 0;
        break;

    case 'o':
    case 'x':
        instruction->operation = OR;
        instruction->mode = 0b0011;
        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
            setInmediate(instruction);
        }

        instruction->useImmediate = 0;
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

    case 'r':
        instruction->operation = RET;
        instruction->useShift = 0;
        instruction->useImmediate = 0;
        break;

    case 'n':
        if (strstr(instruction->disassembled, "t"))
        {
            instruction->operation = NOT;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
            instruction->mode = 0b0011;
            break;
        }
        else if (strstr(instruction->disassembled, "g"))
        {
            instruction->operation = NEG;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
            instruction->mode = 0b0011;
            break;
        }
        else
        {
            instruction->operation = NOP;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
            instruction->mode = 0;
            break;
        }

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

        instruction->useShift = 0;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = 1;
            setInmediate(instruction);
        }

        instruction->useImmediate = 0;

        break;

    case 's':
        if (strstr(instruction->disassembled, "sub"))
        {
            instruction->operation = SUB;
            instruction->mode = 0b0011;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
        }

        else if (strstr(instruction->disassembled, "se") || strstr(instruction->disassembled, "slt") ||
                 strstr(instruction->disassembled, "sn") || strstr(instruction->disassembled, "sg"))
        {
            instruction->operation = SET;
            instruction->mode = 0b0011;
            instruction->useShift = 0;
            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = 1;
                setInmediate(instruction);
            }

            instruction->useImmediate = 0;
        }

        else if (strstr(instruction->disassembled, "sr") || strstr(instruction->disassembled, "sll"))
        {
            instruction->operation = SHIFT;
            instruction->mode = 0b0011;
            instruction->useShift = 1;
            setShift(instruction);
            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = 1;
                setInmediate(instruction);
            }

            instruction->useImmediate = 0;
        }

        else
        {
            instruction->operation = STORE;
            instruction->mode = 0b1100;
            instruction->useShift = 0;
            instruction->useImmediate = 0;
        }
        break;
    }

    return pushToPGL(instruction);
}

static void setInmediate(struct ins32_t *instruction)
{
    char *dummy;
    size_t size;
    size_t startPos = strlen(instruction->disassembled) - 1;
    char *isPresent = strstr(instruction->disassembled, "0x");

    if (isPresent)
    {
        size = startPos - (&instruction->disassembled[startPos] - isPresent);
        dummy = (char *)malloc(sizeof(char) * size);

        strncpy(dummy, &instruction->disassembled[size + 2], size);
        instruction->immediate = atoi(dummy);
        goto liberate;
    }

    while (',' != instruction->disassembled[startPos - 1])
    {
        startPos--;
    }

    dummy = (char *)malloc(sizeof(char) * (strlen(instruction->disassembled) - startPos));
    strncpy(dummy, &instruction->disassembled[startPos], startPos);
    instruction->immediate = atoi(dummy);

liberate:
    free(dummy);
    dummy = NULL;
}

static void setShift(struct ins32_t *instruction)
{
    char *pos = strstr(instruction->disassembled, ",");
    instruction->regToShift[2] = 0;

    strncpy(instruction->regToShift, ++pos, 2);

    if (strstr(instruction->disassembled, "srli"))
    {
        instruction->type = SRLI;
    }

    else if (strstr(instruction->disassembled, "slli"))
    {
        instruction->type = SLLI;
    }

    else if (strstr(instruction->disassembled, "sll"))
    {
        instruction->type = SLL;
    }

    else if (strstr(instruction->disassembled, "srl"))
    {
        instruction->type = SRL;
    }

    else if (strstr(instruction->disassembled, "sra"))
    {
        instruction->type = SRA;
    }

    else
    {
        instruction->type = SRAI;
    }
}
