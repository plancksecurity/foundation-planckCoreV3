# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

.PHONY: db
db: system.db

DICOS = $(wildcard *.csv)

system.db: create_system_db.sql $(DICOS)
	# Keep a backup db around
	-mv -f $@ $@~ 
	sqlite3 -batch $@ < $<
	for c in $(DICOS) ; do echo "$$c" ; echo .import "$$c" wordlist | sqlite3 -batch -csv $@ ; done

.PHONY: install
install: system.db
	mkdir -p `dirname $(SYSTEM_DB)`
	cp system.db $(SYSTEM_DB)

.PHONY: clean
clean:
	-rm -f system.db system.db~
