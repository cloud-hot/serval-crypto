LDFLAGS+=-lservald
CFLAGS+=-I../serval-dna -I../serval-dna/nacl/include -g -DHAVE_BCOPY
OBJS=serval-sign.o serval-verify.o common.o
DEPS=Makefile serval-crypto.h
BINDIR=$(DESTDIR)/usr/bin
LIBDIR=$(DESTDIR)/usr/lib
EXENAME=serval-crypto
LIBNAME=libserval-crypto.so

all: serval-crypto

%.o: %.c $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

libserval-crypto.so: $(DEPS) $(OBJS)
	$(CC) $(CFLAGS) -shared -o $(LIBNAME) $(OBJS) $(LDFLAGS)

serval-crypto: $(DEPS) $(OBJS) main.c $(LIBNAME)
	$(CC) $(CFLAGS) -o $(EXENAME) main.c -L./ -lserval-crypto $(LDFLAGS)

static: $(DEPS) $(OBJS) main.c
	$(CC) $(CFLAGS) -o $(EXENAME) main.c serval-sign.c serval-verify.c common.c $(LDFLAGS)

install: bin-install $(LIBNAME)
	install -d $(LIBDIR)
	install -m 644 $(LIBNAME) $(LIBDIR)

bin-install: $(EXENAME)
	install -d $(BINDIR)
	install -m 755 $(EXENAME) $(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(EXENAME)
	rm -f $(LIBDIR)/$(LIBNAME)

clean:
	rm -f $(EXENAME) *.o core a.out $(LIBNAME)

.PHONY: all clean static install uninstall bin-install
