SERVALD_ROOT=/home/hawkinsw/code/serval/serval-dna/serval-dna/
CFLAGS=-I$(SERVALD_ROOT) -I$(SERVALD_ROOT)/nacl/include
LIBS=-L$(SERVALD_ROOT)/ -lservald
CC=gcc

all: verify

sign:
	echo "Compile sign"

verify: Makefile verify.c verify.h
	$(CC) $(CFLAGS) -o verify verify.c $(LIBS) 	

clean:
	rm -f sign verify *.o core a.out
