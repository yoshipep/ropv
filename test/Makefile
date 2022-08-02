CC=clang
CFLAGS=-O0 -Wall -Werror -fno-stack-protector -fno-inline-functions -fno-PIE -ggdb
LIBNAME=capstone
SOURCES=engine_test.c
OBJS=$(SOURCES:.c=.o)

#$@ = Target de esa regla, en el primer caso es ropv
#$^ = La expansión que hay a la derecha de los dos puntos
#$< = Expansion de uno de los objetos que hay a la derecha de los dos puntos

engine_test: $(OBJS)
	$(CC) $^ $(INCLUDE) -l$(LIBNAME) $(CFLAGS) -o $@

%.o: %.c
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf ./*.o