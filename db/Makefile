# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

db: system.db

dicos=$(wildcard *.csv)

system.db: create_system_db.sql $(dicos)
	-mv -f $@ $@~ 
	sqlite3 -batch $@ < $<
	for c in $(dicos); do echo $$c ; echo .import "$$c" wordlist | sqlite3 -batch -csv $@ ; done

.PHONY: clean install

install: system.db
	mkdir -p `dirname $(SYSTEM_DB)`
	cp system.db $(SYSTEM_DB)

clean:
	rm -f system.db
