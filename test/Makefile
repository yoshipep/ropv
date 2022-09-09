CC=clang
CFLAGS=-O0 -std=c17 -Wall -Wextra -fno-inline-functions -ggdb -D_POSIX_SOURCE
LFLAGS=-l$(LIBNAME) -fno-PIE
LIBNAME=capstone
SOURCES=engine_test.c
OBJS=$(SOURCES:.c=.o)

#$@ = Target de esa regla, en el primer caso es ropv
#$^ = La expansión que hay a la derecha de los dos puntos
#$< = Expansion de uno de los objetos que hay a la derecha de los dos puntos

engine_test: $(OBJS)
	$(CC) $^ $(INCLUDE) $(LFLAGS) -o $@

%.o: %.c
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf ./*.o
