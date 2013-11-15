LDFLAGS+=-lservald
CFLAGS+=-I../serval-dna -I../serval-dna/nacl/include -g -DHAVE_BCOPY -Wall -Wextra
OBJS=serval-sign.o serval-verify.o common.o
DEPS=Makefile serval-crypto.h
BINDIR=$(DESTDIR)/usr/bin
LIBDIR=$(DESTDIR)/usr/lib
INCDIR=$(DESTDIR)/usr/include
EXENAME=serval-crypto
LIBNAME=libserval-crypto.so
INCNAME=serval-crypto.h

all: serval-crypto

%.o: %.c $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

libserval-crypto.so: $(DEPS) $(OBJS)
	$(CC) $(CFLAGS) -shared -o $(LIBNAME) $(OBJS) $(LDFLAGS)

serval-crypto: $(DEPS) $(OBJS) main.c $(LIBNAME)
	$(CC) $(CFLAGS) -o $(EXENAME) main.c -L./ -lserval-crypto $(LDFLAGS)

static: $(DEPS) main.c serval-sign.c serval-verify.c common.c
	$(CC) $(CFLAGS) -o $(EXENAME) main.c serval-sign.c serval-verify.c common.c $(LDFLAGS)

install: bin-install $(LIBNAME) $(INCNAME)
	install -d $(LIBDIR)
	install -m 644 $(LIBNAME) $(LIBDIR)
	install -d $(INCDIR)
	install -m 644 $(INCNAME) $(INCDIR)

bin-install: $(EXENAME)
	install -d $(BINDIR)
	install -m 755 $(EXENAME) $(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(EXENAME)
	rm -f $(LIBDIR)/$(LIBNAME)
	rm -f $(INCDIR)/$(INCNAME)

clean:
	rm -f $(EXENAME) *.o core a.out $(LIBNAME)

.PHONY: all clean static install uninstall bin-install
