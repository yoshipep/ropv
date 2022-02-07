## Synopsis

*ropv* is a Return Oriented Programming (ROP) gadget finder for RISC-V binaries. The program only displays gadgets, it can't create rop chains.

## Installation

To build the program simply run the following command:

    make

## Usage
    Usage: ropv [OPTION...] file
    Tool for ROP explotation (ELF binaries & RISC-V architecture)

        -a all                     Show all gadgets
        -i interesting             Show most interesting gadgets
        -l length                  Set max number of instructions per gadget.
        -s specific                Show specific gadgets. (i.e. related to sp register)
        -v verbose                 Set verbosity.
        -?, --help                 Give this help list
        --usage                    Give a short usage message
        -V, --version              Print program version

    Report bugs to comes.josep2@gmail.com.
	
## TODO

- [x] Choose the best option to disas and extract instructions from the binary.
- [ ] Code the program.
- [ ] Test the program.
- [x] Provide how the program is used.