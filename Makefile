CC      ?= gcc
CFLAGS  ?= -std=c11 -O3 -Wall -Wextra -Werror
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

.PHONY: all install uninstall test clean

all: hshield hshield-supply-scan

hshield: src/hshield.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

hshield-supply-scan: src/hshield_supply_scan.c
	$(CC) $(CFLAGS) -o $@ $< -lz

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
