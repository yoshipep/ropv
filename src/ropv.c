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
#include <stdlib.h>
#include <string.h>

#include "datatypes.h"
#include "disas.h"

static struct argp_option options[] = {
    {"all", 'a', 0, 0, "Show all gadgets. Option selected by default", 0},
    {"ret", 'r', 0, 0, "Show only RET gadgets", 1},
    {"jop", 'j', 0, 0, "Show only JOP gadgets", 2},
    {"sys", 's', 0, 0, "Show only SYSCALL gadgets", 3},
    {0}};

struct arguments args;

static bool genericModeSelected = false;

static bool otherModeSelected = false;

const char *argp_program_version = "ropv v1.0";
const char *argp_program_bug_address = "comes.josep2@gmail.com";
static char doc[] = "Tool for ROP explotation (ELF binaries & RISC-V architecture)";
static char args_doc[] = "file";

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'a':
        if (!otherModeSelected)
        {
            arguments->mode = GENERIC_MODE;
            genericModeSelected = true;
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -a and [-r -j -s] are mutually exclusive");
        }
        break;

    case 'r':
        if (!genericModeSelected)
        {
            arguments->mode = RET_MODE;
            otherModeSelected = true;
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -r and -a are mutually exclusive");
        }
        break;

    case 's':
        if (!genericModeSelected)
        {
            arguments->mode = SYSCALL_MODE;
            otherModeSelected = true;
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -s and -a are mutually exclusive");
        }
        break;

    case 'j':
        if (!genericModeSelected)
        {
            arguments->mode = JOP_MODE;
            otherModeSelected = true;
        }
        else
        {
            argp_failure(state, 1, 1, "Invalid argument combination. Options -j and -a are mutually exclusive");
        }
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

int main(int argc, char *argv[])
{
    memset(&args, 0x0, sizeof(struct arguments));
    args.mode = GENERIC_MODE;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    return disassemble(args.file);
}
