include ../Makefile.conf

db: system.db

system.db: create_system_db.sql
	sqlite3 -batch $@ < $<
	echo .import en.csv wordlist | sqlite3 -batch -csv $@
	echo .import de.csv wordlist | sqlite3 -batch -csv $@

.PHONY: clean install

install: system.db
	cp system.db $(SYSTEM_DB)

clean:
	rm -f system.db
