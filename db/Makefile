# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../default.conf

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
	mkdir -p `dirname $(SYSTEM_DB)`
	cp system.db $(SYSTEM_DB)

.PHONY: clean
clean:
	rm -f system.db system.db~
