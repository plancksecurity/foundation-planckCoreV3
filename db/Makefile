include ../Makefile.conf

db: system.db

system.db: create_system_db.sql
	sqlite3 -batch $@ < $<
	for c in *.csv ; do echo $$c ; echo .import "$$c" wordlist | sqlite3 -batch -csv $@ ; done

.PHONY: clean install

install: system.db
	cp system.db $(SYSTEM_DB)

clean:
	rm -f system.db
