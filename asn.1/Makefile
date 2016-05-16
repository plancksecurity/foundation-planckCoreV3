include ../Makefile.conf

all: Message.c

%.o: %.c %.h
	$(CC) $(CFLAGS) -I$(ASN1C_INCLUDE) -c $< -o $@

Message.c: devicegroup.asn1
	$(ASN1C) -fcompound-names -pdu=PEP.Message pEp.asn1 $<

.PHONY: clean

clean:
	rm -f *.o *.c *.h *.sample
