CC      ?= gcc
CFLAGS  ?= -std=c11 -O3 -Wall -Wextra -Werror

.PHONY: all test clean

all: hshield hshield-supply-scan

hshield: src/hshield.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

hshield-supply-scan: src/hshield_supply_scan.c
	$(CC) $(CFLAGS) -o $@ $< -lz

test: all
	python3 -m unittest discover -s tests -v

clean:
	rm -f hshield hshield-supply-scan
