include ../Makefile.conf

all: Beacon.c Beacon.h

%.o: %.c %.h
	$(CC) $(CFLAGS) -I$(ASN1C_INCLUDE) -c $< -o $@

Beacon.c Beacon.h: devicegroup.asn1
	$(ASN1C) -gen-PER -fcompound-names pEp.asn1 $<

.PHONY: clean

clean:
	rm -f *.o *.c *.h *.sample
