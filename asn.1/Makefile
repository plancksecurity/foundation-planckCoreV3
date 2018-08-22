# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../default.conf

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

all: generate
	make libasn1.a

libasn1.a: $(ALL_OBJECTS)
	ar -rc $@ $(ALL_OBJECTS)

generate: Sync.c
	rm -f converter-sample.c

%.o: %.c %.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -I. -I$(ASN1C_INC) -c $< -o $@

Sync.c: sync.asn1 keysync.asn1 pEp.asn1
	$(ASN1C) -gen-PER -fincludes-quoted -fcompound-names -pdu=PEP.Message pEp.asn1 keysync.asn1 $<

sync.asn1 keysync.asn1 pEp.asn1:
	cp -f ../sync/generated/*.asn1 ../asn.1

.PHONY: clean install uninstall tags

clean:
	rm -f *.a *.o *.c *.h *.sample sync.asn1 keysync.asn1

install:

uninstall:

tags:
	ctags *.c *.h
