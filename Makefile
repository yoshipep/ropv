CC=gcc
CFLAGS=-O0 #-Wall -O0 -ggdb #-O2 -fPIE -Wl,-pie -D_FORTIFY_SOURCE=2 -fstack-protector # Comprobar la necesidad de los dos ultimos flags
INCLUDE=-I ./include
DBG=-Wall -O0 -ggdb
SOURCES=./src/main.c ./src/disas.c
OBJS=$(SOURCES:.c=.o)

#$@ = Target de esa regla, en el primer caso es main
#$^ = La expansión que hay a la derecha de los dos puntos
#$< = Expansion de uno de los objetos que hay a la derecha de los dos puntos

ropv: $(OBJS)
	$(CC) $^ $(INCLUDE) $(CFLAGS) -o $@

debug: $(OBJS)
	$(CC) $^ $(INCLUDE) $(DBG) -o $@

%.o: %.c
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf *.o


