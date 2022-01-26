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

#include "disas.h"

inline uint8_t checkArch(Elf32_Half arch)
{
    return arch == 243;
}

inline uint8_t getBits(Elf32_Ehdr *header)
{
    return (*header).e_ident[EI_CLASS] == 2 ? 64 : 32;
}

uint8_t process_elf(const char *elfFile)
{
    Elf32_Ehdr header;
    FILE *file;
    uint8_t res = 1;

    file = fopen(elfFile, "rb");
    if (file)
    {
        // read the header
        fread(&header, sizeof(header), 1, file);

        // check so its really an elf file
        if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0)
        {
            if (checkArch(header.e_machine))
            {
                if (getBits(&header) == 32)
                {
                    res = 0;
                }
                else
                {
                    fprintf(STDERR_FILENO, "Bitness not suported\n");
                }
            }
            else
            {
                fprintf(STDERR_FILENO, "Bad architecture\n");
            }
        }
        else
        {
            fprintf(STDERR_FILENO, "Not an ELF file\n");
        }
    }
    close(file);
    return res;
}

uint8_t disassemble(const char *elfFile)
{
    pid_t child;
    int returnStatus;
    char args[strlen(elfFile) + 3];
    int fd, tempfd;

    stpcpy(stpcpy(args, "-d "), elfFile);
    fd = open("/tmp/disas", O_RDWR | O_CREAT, DEFAULT_PERM);
    if (fd)
    {
        tempfd = open("/dev/null", O_WRONLY);
        if (!tempfd)
        {
            fprintf(STDERR_FILENO, "Unable to open /dev/null\n");
        }

        if (process_elf(elfFile))
        {
            return 1;
        }

        child = fork();

        if (child == 0)
        {
            dup2(fd, STDOUT_FILENO);
            dup2(tempfd, STDERR_FILENO);
            execve("/opt/rv32/bin/riscv32-unknown-linux-gnu-objdump", args, NULL);
        }

        close(fd);
        close(tempfd);
        waitpid(child, &returnStatus, 0);

        if (!returnStatus)
        {
            fprintf(STDERR_FILENO, "Program failed\n");
            return 1;
        }

        return parseContent("/tmp/disas.s");
    }
    else
    {
        fprintf(STDERR_FILENO, "Unable to create a dummy file\n");
        close(fd);
        return 1;
    }
}

uint8_t parseContent(const char *assemblyFile)
{

    FILE *file;
    size_t len = 0;
    ssize_t read;
    char *line;

    file = fopen(assemblyFile, "r");

    if (!file)
    {
        fprintf(STDERR_FILENO, "Unable to open the dummy file\n");
        fclose(file);
        return 1;
    }
    unlink(assemblyFile);

    while (read = getline(&line, &len, file) != -1)
    {
        printf("Retrieved line of length %zu:\n", read);
        printf("%s", line);
    }
    return 0;
}