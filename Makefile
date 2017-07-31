# this file is under GNU General Public License v3.0
# see LICENSE.txt

include Makefile.conf

# add it to the environment of all executed programs:
export YML_PATH


all:
	$(MAKE) -C asn.1 generate
	$(MAKE) -C asn.1
	$(MAKE) -C sync
	$(MAKE) -C src all

.PHONY: clean build_test test package install uninstall db

install: all
	$(MAKE) -C src install
	$(MAKE) -C asn.1 install

uninstall:
	$(MAKE) -C src uninstall

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C db clean
	$(MAKE) -C sync clean
	$(MAKE) -C asn.1 clean

test: all
	$(MAKE) -C test test
	$(MAKE) -C test unit_tests

unit_tests: all
	$(MAKE) -C test unit_tests

package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 pEpEngine

db:
	$(MAKE) -C db db

windist:
ifneq ($(BUILD_FOR),Windoze)
	@echo use BUILD_FOR=Windoze \(did you forget -e ?\)
else
	make clean
	$(MAKE) all
	$(MAKE) -C test all
	zip -j pEpEngine-dist.zip src/pEpEngine.h src/keymanagement.h src/pEpEngine.dll src/pEpEngine.def test/pEpEngineTest.exe test/*.asc test/*.key db/*.db test/*.txt test/*.asc src/*.sql
endif

