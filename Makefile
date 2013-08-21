LDFLAGS+=-lservald
CFLAGS+=-I../serval-dna -I../serval-dna/nacl/include -g
OBJS=serval-sign.o serval-verify.o

all: serval-sign serval-verify

serval-sign: Makefile sign.c serval-crypto.h
	$(CC) $(CFLAGS) -o serval-sign sign.c common.c $(LDFLAGS)

serval-verify: Makefile verify.c serval-crypto.h
	$(CC) $(CFLAGS) -o serval-verify verify.c common.c $(LDFLAGS)

serval-sign.o: Makefile sign.c
	$(CC) $(CFLAGS) -DSHARED -fPIC -c -o serval-sign.o sign.c

serval-verify.o: Makefile verify.c
	$(CC) $(CFLAGS) -DSHARED -fPIC -c -o serval-verify.o verify.c

libserval-crypto.so: Makefile serval-verify.o serval-sign.o
	$(CC) $(CFLAGS) -shared -o libserval-crypto.so $(OBJS) $(LDFLAGS)

clean:
	rm -f serval-sign serval-verify *.o core a.out libserval-crypto.so

.PHONY: all clean