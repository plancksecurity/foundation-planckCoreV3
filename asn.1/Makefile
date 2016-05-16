include ../Makefile.conf

all: DeviceGroup-Protocol.c

%.o: %.c %.h
	$(CC) $(CFLAGS) -I$(ASN1C_INCLUDE) -c $< -o $@

DeviceGroup-Protocol.c: devicegroup.asn1
	$(ASN1C) -fcompound-names -pdu=PEP.Message pEp.asn1 $<

.PHONY: clean

clean:
	rm -f *.o *.c *.h *.sample
