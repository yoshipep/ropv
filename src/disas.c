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
#include "gadgets.h"

static __attribute__((always_inline)) inline uint8_t checkArch(Elf32_Half arch);

static __attribute__((always_inline)) inline uint8_t getBits(Elf32_Ehdr *header);

static uint8_t process_elf(char *elfFile);

static uint8_t parseContent(char *assemblyFile);

static inline __attribute__((always_inline)) uint8_t checkArch(Elf32_Half arch)
{
    return arch == 243;
}

static inline __attribute__((always_inline)) uint8_t getBits(Elf32_Ehdr *header)
{
    /*If value equals to 2, the binary is from a 64 bits arch*/
    return (*header).e_ident[EI_CLASS] != 2 ? 1 : 0;
}

static uint8_t process_elf(char *elfFile)
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
                        if (verbose)
                        {
                            puts("[+] Checking program headers");
                        }

                        if (header.e_phnum)
                        {
                            res = 0;
                        }
                        else
                        {
                            fprintf(stderr, "[-] Invalid ELF file\n");
                        }
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

uint8_t disassemble(char *elfFile)
{
    pid_t child;
    int returnStatus, fd, tempfd;

    char *args[] = {"/opt/rv32/bin/riscv32-unknown-linux-gnu-objdump", "-d", elfFile, NULL};

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
            goto fail;
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
    if (fcntl(fd, F_GETFD))
    {
        close(fd);
    }

    if (fcntl(tempfd, F_GETFD))
    {
        close(tempfd);
    }
    return 1;
}

static uint8_t parseContent(char *assemblyFile)
{

    FILE *file;
    char *line, *address, *pos;
    uint8_t nIns, nTabs;
    int32_t baseAddress, endPos;
    size_t startPos;
    uint8_t start = 0;
    size_t len = 0;
    ssize_t read = -1;

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
                if (0x9 == line[startPos])
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

            if (RET == current.type)
            {
                start = 0;
                processGadgets();
            }

            nIns += 4;
        }

    } while (read);

    return 0;
}
