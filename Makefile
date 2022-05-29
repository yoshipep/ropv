CC=gcc
CFLAGS=-Wall -Wextra -O0 -ggdb -fsanitize=address
INCLUDE=-I ./include
TESTDIR=test
SOURCES=./test/main.c ./src/hashtable.c
OBJS=$(SOURCES:.c=.o)

#$@ = Target de esa regla, en el primer caso es main
#$^ = La expansión que hay a la derecha de los dos puntos
#$< = Expansion de uno de los objetos que hay a la derecha de los dos puntos

$(TESTDIR)/hashtable: $(OBJS)
	$(CC) $^ $(INCLUDE) $(CFLAGS) -o $@

%.o: %.c
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf ./src/*.o
	rm -rf ./test/*.o


