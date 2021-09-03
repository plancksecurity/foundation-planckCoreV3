# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../Makefile.conf

.PHONY: db
db: system.db

DICOS = $(wildcard *.csv)

# The 'mv' keeps a backup db around
system.db: create_system_db.sql $(DICOS)
	-mv -f $@ $@~ 
	sqlite3 -batch $@ < $<
	for c in $(DICOS) ; do echo "$$c" ; echo .import "$$c" wordlist | sqlite3 -batch -csv $@ ; done

.PHONY: install
install: system.db
	# Notice that the expansion of these make variables may still contain
	# shell variable occurrences, to be expanded in their turn.  This
	# serves to leave more freedom to the deployment engineer.
	mkdir -p "$(DESTDIR)$(PER_MACHINE_DIRECTORY)"
	cp system.db "$(DESTDIR)$(PER_MACHINE_DIRECTORY)"

.PHONY: clean
clean:
	rm -f system.db system.db~
