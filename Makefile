LDFLAGS+=-lservald
CFLAGS+=-I../serval-dna -I../serval-dna/nacl/include -g -DHAVE_BCOPY
OBJS=serval-sign.o serval-verify.o common.o
DEPS=Makefile serval-crypto.h

all: serval-sign serval-verify

%.o: %.c $(DEPS)
	$(CC) -DSHARED -fPIC -c -o $@ $< $(CFLAGS)

serval-sign: $(DEPS) serval-sign.c common.c
	$(CC) $(CFLAGS) -o serval-sign serval-sign.c common.c $(LDFLAGS)

serval-verify: $(DEPS) serval-verify.c common.c
	$(CC) $(CFLAGS) -o serval-verify serval-verify.c common.c $(LDFLAGS)

libserval-crypto.so: $(DEPS) $(OBJS)
	$(CC) $(CFLAGS) -shared -o libserval-crypto.so $(OBJS) $(LDFLAGS)

clean:
	rm -f serval-sign serval-verify *.o core a.out libserval-crypto.so

.PHONY: all clean
