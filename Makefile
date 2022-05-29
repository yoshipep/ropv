CC=gcc
CFLAGS=-O2 -fPIE -pie -D_FORTIFY_SOURCE=2 -fstack-protector
INCLUDE=-I ./include
RELDIR=release
DBG=0
DBGDIR=debug
DBGCFLAGS=-Wall -Wextra -O0 -ggdb -fsanitize=address
TESTDIR=test
SOURCES=./src/ropv.c ./src/disas.c ./src/gadget.c ./src/node.c
OBJS=$(SOURCES:.c=.o)
TESTSOURCES=./test/hashtable_test.c ./src/hashtable.c
TESTOBJS=$(TESTSOURCES:.c=.o)

#$@ = Target de esa regla, en el primer caso es main
#$^ = La expansión que hay a la derecha de los dos puntos
#$< = Expansion de uno de los objetos que hay a la derecha de los dos puntos

$(RELDIR)/ropv: $(OBJS)
	$(CC) $^ $(INCLUDE) $(CFLAGS) -o $@

$(DBGDIR)/debug: $(OBJS)
	$DBG=1
	$(CC) $^ $(INCLUDE) $(DBGCFLAGS) -o $@

$(TESTDIR)/hashtable_test: $(TESTOBJS)
	$(CC) $^ $(INCLUDE) $(CFLAGS) -o $@

%.o: %.c
ifeq ($(DBG), 1)
	$(CC) -c $< $(INCLUDE) $(DBGCFLAGS) -o $@
else
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@
endif

.PHONY: clean

clean:
	rm -rf ./src/*.o
	rm -rf ./test/*.o


