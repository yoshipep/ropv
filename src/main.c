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

#include <argp.h>
#include <stdint.h>
#include <stdlib.h>

#include "disas.h"

const char *argp_program_version = "ropv v1.0";
const char *argp_program_bug_address = "comes.josep2@gmail.com";
static char doc[] = "Tool for ROP explotation (ELF binaries & RISC-V architecture)";
static char args_doc[] = "file";
static struct argp_option options[] = {
    {0, 'l', "length", 0, "Set max number of instructions per gadget."},
    {0, 't', "threads", 0, "Set thread number."},
    {0, 'v', "verbose", 0, "Set verbosity."},
    {0}};

struct arguments
{
    uint8_t length;
    char *file;
    uint8_t nThreads;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'l':
        arguments->length = atoi(arg);
        break;

    case 't':
        arguments->nThreads = atoi(arg);
        break;

    case 'v':
        #define VERBOSE
        break;

    case ARGP_KEY_ARG:
        if (state->arg_num > 1)
        {
            argp_usage(state);
        }
        else
        {
            arguments->file = arg;
        }
        break;

    case ARGP_KEY_END:
        if (state->arg_num < 1)
        {
            argp_usage(state);
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char **argv)
{
    struct arguments args;

    args.length = 3; //default length: 3 ins / gadget
    argp_parse(&argp, argc, argv, 0, 0, &args);

    printf("%d\t%s\t%d\n", args.length, args.file, args.nThreads);
    return 0;
}