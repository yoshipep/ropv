CC=gcc
CFLAGS=-I ./include -O2 -Wall -fPIE
SOURCES=./src/main.c ./src/disas.c
OBJS=$(SOURCES:.c=.o)

main: $(OBJS)
	$(CC) $^ $(CFLAGS) -o $@

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf *.o


