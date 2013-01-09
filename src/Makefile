all: verify sign

CFLAGS+= -O0

sign: Makefile sign.c
	$(CC) $(CFLAGS) -o serval-sign sign.c $(LDFLAGS)

verify: Makefile verify.c
	$(CC) $(CFLAGS) -o serval-verify verify.c $(LDFLAGS) 	

clean:
	rm -f serval-sign serval-verify *.o core a.out
