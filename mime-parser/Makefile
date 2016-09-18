include ../Makefile.conf

all: generate
	cp mailmime.peg.c.src ../src/.

generate: 
	peg mailmime.peg -o mailmime.peg.c.src

.PHONY: clean

clean:
	rm -f mailmime.peg.c
