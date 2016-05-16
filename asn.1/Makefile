include ../Makefile.conf

all: Message.c Message.h

%.o: %.c %.h
	$(CC) $(CFLAGS) -I$(ASN1C_INCLUDE) -c $< -o $@

Message.c Message.h: devicegroup.asn1
	$(ASN1C) -fcompound-names -pdu=PEP.Message pEp.asn1 $<

.PHONY: clean

clean:
	rm -f *.o *.c *.h *.sample
