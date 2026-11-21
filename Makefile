CC       ?= cc
CFLAGS   ?= -O3 -Wall -Wextra -Werror
CPPFLAGS ?=
LDFLAGS  ?=
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

OPENSSL_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs libcrypto 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS   := -lcrypto
endif

ZLIB_CFLAGS := $(shell pkg-config --cflags zlib 2>/dev/null)
ZLIB_LIBS   := $(shell pkg-config --libs zlib 2>/dev/null)
ifeq ($(strip $(ZLIB_LIBS)),)
ZLIB_LIBS   := -lz
endif

ALL_CFLAGS := -std=c11 $(CPPFLAGS) $(CFLAGS)

.PHONY: all install uninstall test clean

all: hshield hshield-supply-scan

hshield: src/hshield.c
	$(CC) $(ALL_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(LDFLAGS) $(OPENSSL_LIBS)

hshield-supply-scan: src/hshield_supply_scan.c
	$(CC) $(ALL_CFLAGS) $(ZLIB_CFLAGS) -o $@ $< $(LDFLAGS) $(ZLIB_LIBS)

install: all
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 hshield "$(DESTDIR)$(BINDIR)/hshield"
	install -m 0755 hshield-supply-scan "$(DESTDIR)$(BINDIR)/hshield-supply-scan"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/hshield" "$(DESTDIR)$(BINDIR)/hshield-supply-scan"

test: all
	python3 -m unittest discover -s tests -v

clean:
	rm -f hshield hshield-supply-scan
