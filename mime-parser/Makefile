include ../Makefile.conf

all: generate
	cp mailmime.leg.c.src ../src/.

generate: 
	leg mailmime.leg -o mailmime.leg.c.src

.PHONY: clean

clean:
	rm -f mailmime.leg.c
