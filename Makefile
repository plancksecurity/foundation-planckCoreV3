# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

export BUILD_CONFIG:=$(CURDIR)/build-config
include Makefile.conf

export YML2_PATH

HERE_REL := $(notdir $(CURDIR))

.PHONY: all
all:
	$(MAKE) -C asn.1 generate
	$(MAKE) -C asn.1
	$(MAKE) -C sync
	$(MAKE) -C src all

.PHONY: install
install: all
	$(MAKE) -C src install
	$(MAKE) -C asn.1 install

.PHONY: uninstall
uninstall:
	$(MAKE) -C src uninstall
	$(MAKE) -C asn.1 uninstall

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C db clean
	$(MAKE) -C sync clean
	$(MAKE) -C asn.1 clean

.PHONY: test
test: all
	$(MAKE) -C test test
	$(MAKE) -C test unit_tests

.PHONY: unit_tests
unit_tests: all
	$(MAKE) -C test unit_tests

.PHONY: package
package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 "$(HERE_REL)"

.PHONY: db
db:
	$(MAKE) -C db db
