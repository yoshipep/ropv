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

#include "datatypes.h"
#include "disas.h"

const char *argp_program_version = "ropv v1.0";
const char *argp_program_bug_address = "comes.josep2@gmail.com";
static char doc[] = "Tool for ROP explotation (ELF binaries & RISC-V architecture)";
static char args_doc[] = "file";
static struct argp_option options[] = {
    {0, 'l', "length", 0, "Set max number of instructions per gadget."},
    {0, 'a', "all", 0, "Show all gadgets"},
    {0, 'i', "interesting", 0, "Show most interesting gadgets"},
    {0, 's', "specific", 0, "Show specific gadgets. (i.e. related to sp register)"},
    {0, 'v', "verbose", 0, "Set verbosity."},
    {0}};

uint8_t verbose;

static char mutuallyExclusive = 'z';

static uint8_t arg_count = 4;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    arguments->mode = FULL_MODE;
    int tmp;

    switch (key)
    {
    case 'l':
        tmp = atoi(arg);
        if (tmp <= 0 || tmp >= 5)
        {
            arguments->length = DEFAULT_LENGTH;
        }
        else
        {
            arguments->length = tmp;
        }
        break;

    case 'a':
        if (mutuallyExclusive == 'z')
        {
            arguments->mode = FULL_MODE;
            mutuallyExclusive = 'a';
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -a, -s and -i are mutually exclusive.");
        }
        break;
    case 'i':
        if (mutuallyExclusive == 'z')
        {
            arguments->mode = INTEREST_MODE;
            mutuallyExclusive = 'i';
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -a, -s and -i are mutually exclusive.");
        }
        break;

    case 's':
        if (mutuallyExclusive == 'z')
        {
            arguments->mode = SPECIFIC_MODE;
            mutuallyExclusive = 's';
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -a, -s and -i are mutually exclusive.");
        }
        break;

    case 'v':
        verbose = 1;
        break;

    case ARGP_KEY_ARG:
        if (state->arg_num >= 1)
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

    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (args.length != DEFAULT_LENGTH)
    {
        args.length = args.length;
    }

    printf("%d\t%s\t%d\n", args.length, args.file, args.mode);
    disassemble("/home/josep/Desktop/ropv/files/example");
    return 0;
}