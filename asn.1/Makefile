# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

ifeq ($(BUILD_ON),Linux)
ifeq ($(BUILD_FOR),Linux)

CC=gcc
CFLAGS?=-fPIC
else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif
endif

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

libasn1.a: $(ALL_OBJECTS)
	ar -rc $@ $(ALL_OBJECTS)

generate: Sync-Protocols.c
	rm -f converter-sample.c

%.o: %.c %.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -I. -I$(ASN1C_INCLUDE) -c $< -o $@

Sync-Protocols.c: protocols.asn1 devicegroup.asn1 pEp.asn1
	$(ASN1C) -gen-PER -fincludes-quoted -fcompound-names -pdu=PEP.Message pEp.asn1 devicegroup.asn1 $<

.PHONY: clean

clean:
	rm -f *.a *.o *.c *.h *.sample

install: libasn1.a
	cp $< $(PREFIX)/lib/
