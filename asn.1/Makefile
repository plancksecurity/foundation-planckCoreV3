# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))
CPPFLAGS+=$(CPPFLAGS_GENERATED)
ASN1C_INC+= -I.

.PHONY: all clean install uninstall

all: Sync.c Distribution.c
	$(MAKE) libasn1.a

libasn1.a: $(ALL_OBJECTS)
	$(AR) -rc $@ $(ALL_OBJECTS)

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OPTIMIZE) $(ASN1C_INC) -c $< -o $@

Sync.c: sync.asn1 keysync.asn1 pEp.asn1
	$(ASN1C) -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 $<
	rm -f converter-sample.c
	touch Sync.c

Distribution.c: distribution.asn1 keyreset.asn1 managedgroup.asn1 pEp.asn1
	$(ASN1C) -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keyreset.asn1 managedgroup.asn1 $<
	rm -f converter-sample.c
	touch Distribution.c

clean:
	rm -f *.a *.o *.c *.h *.sample sync.asn1 keysync.asn1 distribution.asn1 keyreset.asn1 managedgroup.asn1

install:

uninstall:

tags: $(wildcard *.c) $(wildcard *.h)
	ctags --sort=yes *.c *.h
