# NOTICE

This program was a Bachelor's Degree Final Project that I finished last year. I no longer mantain it so it may contain bugs and has limited functionality as I didn't implement all the features I wanted to. The last working branch is _capstone_. In addition, the paper is available [here](https://jcomes.org/ropv)

## Synopsis

_ropv_ is a Return Oriented Programming (ROP) gadget finder for RISC-V binaries. The program only displays gadgets, it can't create rop chains.

## Installation

First you will need the Capstone Engine, available through this [link](https://github.com/capstone-engine/capstone). You can also find it in this repo.

To build the program execute the Makefile

## Usage

    Usage: ropv [OPTION...] file
    Tool for ROP explotation (ELF binaries & RISC-V architecture)

        -a, --all                  Show all gadgets. Option selected by default
        -r, --ret                  Show only RET gadgets
        -j, --jop                  Show only JOP gadgets
        -s, --sys                  Show only SYSCALL gadgets
        -?, --help                 Give this help list
        --usage                    Give a short usage message
        -V, --version              Print program version

    Report bugs to comes.josep2@gmail.com.
