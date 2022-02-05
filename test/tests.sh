#!/bin/bash

include="-I ../include"
flags="-Wall -O0 -ggdb"
echo "[+] Making Stack test"

gcc $include $flags -c ../src/node.c
gcc $include $flags -c ../src/stack.c
gcc $include $flags -o stackTest TestStack.c stack.o node.o

echo "[!] Done"

echo "[+] Making Node test"

gcc $include $flags -o nodeTest TestNode.c node.o
#rm *.o

echo "[!] Done"