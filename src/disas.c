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
#include "disas.h"
#include "errors.h"
#include "gadget.h"

#define DEFAULT_PERM 0644
#define DUMMY_FILE "/tmp/disas.s"

static void setInmediate(struct ins32_t *instruction);

static uint8_t process_elf(char *elfFile);

static uint8_t parseContent(char *assemblyFile);

static __attribute__((always_inline)) inline void removeExtraInfo(struct ins32_t *instruction);

static inline void setRegDest(struct ins32_t *instruction);

static __attribute__((always_inline)) inline bool checkArch(Elf32_Half arch);

static __attribute__((always_inline)) inline bool getBits(Elf32_Ehdr *header);

static __attribute__((always_inline)) inline uint16_t pushToPGL(struct ins32_t *instruction);

static inline uint16_t pushToPGL(struct ins32_t *instruction)
{
    // Inserts new record in the list and return it's index
    static uint8_t pos = 0;
    preliminary_gadget_list[pos % 100] = instruction;
    return pos++ % 100;
}

static inline bool checkArch(Elf32_Half arch)
{
    // Return true if the binary is from the RISC-V arch
    return arch == 243;
}

static inline bool getBits(Elf32_Ehdr *header)
{
    // If value equals to 2, the binary is from a 64 bits arch
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

    // Read the ELF header
    if (!fread(&header, sizeof(header), 1, file))
    {
        fprintf(stderr, "[-] Error while reading the ELF file\n");
        res = EIO;
        goto close;
    }

    // Check so its really an elf file
    if (!memcmp(header.e_ident, ELFMAG, SELFMAG) == 0)
    {
        fprintf(stderr, "[-] Not an ELF file\n");
        res = EIFILE;
        goto close;
    }

    // Check the arch
    if (!checkArch(header.e_machine))
    {
        fprintf(stderr, "[-] Bad architecture\n");
        res = EBARCH;
        goto close;
    }

    // Check the bitness
    if (getBits(&header))
    {
        fprintf(stderr, "[-] Bitness not suported\n");
        res = EBIT;
        goto close;
    }

    // Check if the program has any program header
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

    // Checks the file provided
    if (process_elf(elfFile))
    {
        goto fail;
    }

    child = fork();

    if (0 == child)
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

    // Wait for the child
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
    uint8_t nTabs, bytes, last;
    uint16_t offset;
    int32_t baseAddress, endPos;
    ins32_t *current;
    size_t startPos;
    bool start = false, isEnd = false;
    uint8_t startProcessing = 0;
    size_t len = 0;
    ssize_t read = -1;

    file = fopen(assemblyFile, "r");

    if (!file)
    {
        fprintf(stderr, "[-] Unable to open the dummy file\n");
        return EOPEN;
    }
    unlink(assemblyFile);
    list = create();
    spDuplicated = create();

    do
    {
        read = getline(&line, &len, file) != -1;
        if (!read)
        {
            break;
        }

        // Start processing from .text section
        if (!strstr(line, ".text:") && !startProcessing)
        {
            continue;
        }
        startProcessing = 1;

        // Ensures ret is not the last instruction
        if (isEnd && !strstr(line, "\n"))
        {
            start = true;
            isEnd = false;
        }

        // Check if has reached the end of a function
        if ((0 == strcmp(line, "\n")) || strstr(line, "...") ||
            strstr(line, "unimp"))
        {
            isEnd = false;
            start = false;
            continue;
        }

        // Check if the line is the start of a function
        if (!start && (':' == line[strlen(line) - 2]) &&
            ((line[0] - '0' >= 0) && (line[0] - '0' <= 9)))
        {
            start = true;
            address = calloc(9, sizeof(char));
            address = strncpy(address, line, 8);
            // Stores the base address of the function
            baseAddress = strtol(address, NULL, 0x10);
            free(address);
            address = NULL;
            offset = 0;
            continue;
        }

        // If the current line belongs to a function
        if (start)
        {
            startPos = 0;
            nTabs = 0;

            // Check if the current line has comments.
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

            // Advances the start pointer. At the end line[startpos] till line[endPos]
            // will have our instruction disassembled
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
            current = (ins32_t *)calloc(1, sizeof(ins32_t));
            current->address = baseAddress + offset;
            current->disassembled = (char *)calloc((endPos - startPos) + 1, sizeof(char));
            strncpy(current->disassembled, &line[startPos], endPos - startPos);
            last = fillData(current);

            if (JMP == current->operation)
            {
                removeExtraInfo(current);
            }

            opcode = strstr(line, "\t") + 1;
            while (0x20 != *opcode++)
            {
                bytes++;
            }

            current->isCompressed = (4 == bytes) ? true : false;

            switch (args.mode)
            {
            case JOP_MODE:
                if ((JMP == current->operation) &&
                    strstr(current->disassembled, "jr"))
                {
                    processGadgets(last, current->operation);
                    start = false;
                    isEnd = true;
                }
                break;

            case SYSCALL_MODE:
                if (SYSCALL == current->operation)
                {
                    processGadgets(last, current->operation);
                    start = false;
                    isEnd = true;
                }
                break;

            case RET_MODE:
                if (RET == current->operation)
                {
                    processGadgets(last, current->operation);
                    start = false;
                    isEnd = true;
                }
                break;

            case GENERIC_MODE:
                if ((RET == current->operation) ||
                    (SYSCALL == current->operation) ||
                    ((JMP == current->operation) &&
                     strstr(current->disassembled, "jr")))
                {
                    processGadgets(last, current->operation);
                    start = false;
                    isEnd = true;
                }
                break;

            default:
                break;
            }

            offset += bytes / 2;
        }

    } while (read);

    printContent(list);
    return 0;
}

uint8_t fillData(struct ins32_t *instruction)
{
    char start = instruction->disassembled[0];

    switch (start)
    {
    case 'l':
        if (!strstr(instruction->disassembled, ".w"))
        {
            instruction->operation = LOAD;
        }

        else
        {
            instruction->operation = ATOMIC;
        }
        instruction->useImmediate = false;
        break;

    case 'b':
        instruction->operation = CMP;
        instruction->useImmediate = false;
        break;

    case 'j':
    case 't':
        if (strstr(instruction->disassembled, "jal"))
        {
            instruction->operation = CALL;
        }

        else
        {
            instruction->operation = JMP;
        }

        instruction->useImmediate = false;
        break;

    case 'o':
    case 'x':
        instruction->operation = OR;
        if (strstr(instruction->disassembled, "i"))
        {
            instruction->useImmediate = true;
            setInmediate(instruction);
        }

        else
        {
            instruction->useImmediate = false;
        }
        break;

    case 'e':
        if (strstr(instruction->disassembled, "ecall"))
        {
            instruction->operation = SYSCALL;
        }

        else
        {
            instruction->operation = BRK;
        }
        instruction->useImmediate = false;
        break;

    case 'r':
        if (!strstr(instruction->disassembled, "remu"))
        {
            instruction->operation = RET;
        }

        else
        {
            instruction->operation = MUL;
        }
        instruction->useImmediate = false;
        break;

    case 'n':
        if (strstr(instruction->disassembled, "t"))
        {
            instruction->operation = NOT;
        }

        else if (strstr(instruction->disassembled, "g"))
        {
            instruction->operation = NEG;
        }

        else
        {
            instruction->operation = NOP;
        }
        instruction->useImmediate = false;
        break;

    case 'm':
        if (!strstr(instruction->disassembled, "mul"))
        {
            instruction->operation = MOV;
        }

        else
        {
            instruction->operation = MUL;
        }
        instruction->useImmediate = false;
        break;

    case 'a':
        if (!strstr(instruction->disassembled, ".w"))
        {
            if (strstr(instruction->disassembled, "ad") || strstr(instruction->disassembled, "au"))
            {
                instruction->operation = ADD;
            }

            else
            {
                instruction->operation = AND;
            }

            if (strstr(instruction->disassembled, "i"))
            {
                instruction->useImmediate = true;
                setInmediate(instruction);
            }

            else
            {
                instruction->useImmediate = false;
            }
        }

        else
        {
            instruction->operation = ATOMIC;
            instruction->useImmediate = false;
        }
        break;

    case 'f':
        instruction->operation = IO;
        instruction->useImmediate = false;
        break;

    case 's':
        if (!strstr(instruction->disassembled, ".w"))
        {
            if (strstr(instruction->disassembled, "sub"))
            {
                instruction->operation = SUB;
                instruction->useImmediate = false;
            }

            else if (strstr(instruction->disassembled, "se") || strstr(instruction->disassembled, "slt") ||
                     strstr(instruction->disassembled, "sn") || strstr(instruction->disassembled, "sg"))
            {
                instruction->operation = SET;
                if (strstr(instruction->disassembled, "i"))
                {
                    instruction->useImmediate = true;
                    setInmediate(instruction);
                }

                else
                {
                    instruction->useImmediate = false;
                }
            }

            else if (strstr(instruction->disassembled, "sr") || strstr(instruction->disassembled, "sll"))
            {
                instruction->operation = SHIFT;
                if (strstr(instruction->disassembled, "i"))
                {
                    instruction->useImmediate = true;
                    setInmediate(instruction);
                }

                else
                {
                    instruction->useImmediate = false;
                }
            }

            else
            {
                instruction->operation = STORE;
                instruction->useImmediate = false;
            }
        }

        else
        {
            instruction->operation = ATOMIC;
            instruction->useImmediate = false;
        }
        break;

    case 'd':
        instruction->operation = DIV;
        instruction->useImmediate = false;
        break;

    default:
        instruction->operation = UNSUPORTED;
        break;
    }

    setRegDest(instruction);
    return pushToPGL(instruction);
}

static void setInmediate(struct ins32_t *instruction)
{
    char buf[16];
    memset(buf, 0x0, 16);
    size_t size;
    size_t startPos = strlen(instruction->disassembled) - 1;
    char *isPresent = strstr(instruction->disassembled, "0x");

    if (isPresent)
    {
        isPresent++;
        isPresent++;
        size = strlen(isPresent);
        memcpy(buf, isPresent, size);
        instruction->immediate = atoi(buf);
        return;
    }

    while (',' != instruction->disassembled[startPos - 1])
    {
        startPos--;
    }
    size = strlen(&instruction->disassembled[startPos]);
    memcpy(buf, &instruction->disassembled[startPos], size);
    instruction->immediate = atoi(buf);
}

static inline void setRegDest(struct ins32_t *instruction)
{
    if ((CMP == instruction->operation) || (BRK == instruction->operation) ||
        (RET == instruction->operation) || (ATOMIC == instruction->operation) ||
        (IO == instruction->operation) || (SYSCALL == instruction->operation) ||
        (NOP == instruction->operation) ||
        (UNSUPORTED == instruction->operation))
    {
        return;
    }
    char *pos = strstr(instruction->disassembled, "\t");
    strncpy(instruction->regDest, ++pos, 2);
}

static inline void removeExtraInfo(struct ins32_t *instruction)
{
    char *extra = strstr(instruction->disassembled, "<");

    if (extra)
    {
        extra[0] = 0x0;
    }
}