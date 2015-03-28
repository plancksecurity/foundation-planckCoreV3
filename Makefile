include Makefile.conf

all:
	$(MAKE) -C src all

.PHONY: clean build_test test package install uninstall

install:
	$(MAKE) -C src install

uninstall:
	$(MAKE) -C src uninstall

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean

test: all
	$(MAKE) -C test test
	$(MAKE) -C test unit_tests

unit_tests: all
	$(MAKE) -C test unit_tests

package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 pEpEngine

windist:
ifneq ($(BUILD_FOR),Windoze)
	@echo use BUILD_FOR=Windoze \(did you forget -e ?\)
else
	make clean
	$(MAKE) all
	$(MAKE) -C test all
	zip -j pEpEngine-dist.zip src/pEpEngine.h src/keymanagement.h src/pEpEngine.dll src/pEpEngine.def test/pEpEngineTest.exe test/*.asc test/*.key db/*.db test/*.txt test/*.asc src/*.sql
endif

