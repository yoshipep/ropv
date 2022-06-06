## Synopsis

_ropv_ is a Return Oriented Programming (ROP) gadget finder for RISC-V binaries. The program only displays gadgets, it can't create rop chains.

## Installation

First you will need the RISC-V toolchain, available through this [link](https://github.com/riscv-collab/riscv-gnu-toolchain). You can also find it in this repo.

To build the program execute the Makefile

## Usage

    Usage: ropv [OPTION...] file
    Tool for ROP explotation (ELF binaries & RISC-V architecture)

        -a, --all                  Show all gadgets. Option selected by default
        -i, --interest             Show most interesting gadgets
        -j, --jop                  Enable JOP gadgets
        -?, --help                 Give this help list
        --usage                    Give a short usage message
        -V, --version              Print program version

    Report bugs to comes.josep2@gmail.com.
