####### need to 'make libservald.so' in serval-dna dir, 
####### sudo LD_LIBRARY_PATH=/home/danarky/OTI/commotion/serval-dna/ ./serval-sign message

#SERVALD_ROOT=/home/hawkinsw/code/serval/serval-dna/serval-dna/
SERVALD_ROOT=/home/danarky/OTI/commotion/serval-dna
CFLAGS=-I$(SERVALD_ROOT) -I$(SERVALD_ROOT)/nacl/include -g -O0
LIBS=-L$(SERVALD_ROOT)/ -lservald
CC=gcc

all: verify2 verify sign

sign: Makefile sign.c
	$(CC) $(CFLAGS) -o serval-sign sign.c $(LIBS)

verify: Makefile verify.c verify.h
	$(CC) $(CFLAGS) -o verify verify.c $(LIBS) 	
	
verify2: Makefile verify2.c
	$(CC) $(CFLAGS) -o serval-verify verify2.c $(LIBS) 	

clean:
	rm -f serval-sign verify serval-verify *.o core a.out
