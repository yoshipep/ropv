CC=clang
CFLAGS=-O2 -std=gnu11 -D_FORTIFY_SOURCE=2 -fstack-protector
LFLAGS=-l$(LIBNAME) -fPIE
LIBNAME=capstone
INCLUDE=-I ./include
RELDIR=release
SOURCES=./src/ropv.c ./src/disas.c ./src/gadget.c ./src/node.c
OBJS=$(SOURCES:.c=.o)

#$@ = Target de esa regla, en el primer caso es ropv
#$^ = La expansión que hay a la derecha de los dos puntos
#$< = Expansion de uno de los objetos que hay a la derecha de los dos puntos

$(RELDIR)/ropv: $(OBJS)
	$(CC) $^ $(LFLAGS) -o $@

%.o: %.c
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm -rf ./src/*.o


