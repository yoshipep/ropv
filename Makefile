CC=gcc
CFLAGS=-O3 -fPIE
INCLUDE=-I ./include
DBG=-Wall -O0 -ggdb
SOURCES=./src/main.c ./src/disas.c
OBJS=$(SOURCES:.c=.o)

main: $(OBJS)
	$(CC) $^ $(INCLUDE) $(CFLAGS) -o $@

debug: $(OBJS)
	$(CC) $^ $(INCLUDE) $(DBG) -o $@

%.o: %.c
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf *.o


