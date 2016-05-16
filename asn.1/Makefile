include ../Makefile.conf

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

libasn1.a: $(ALL_OBJECTS)
	ar -rc $@ $(ALL_OBJECTS)

generate: DeviceGroup-Protocol.c
	rm -f converter-sample.c

%.o: %.c %.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -I$(ASN1C_INCLUDE) -c $< -o $@

DeviceGroup-Protocol.c: devicegroup.asn1
	$(ASN1C) -gen-PER -fincludes-quoted -fcompound-names -pdu=PEP.Message pEp.asn1 $<

.PHONY: clean

clean:
	rm -f *.a *.o *.c *.h *.sample
