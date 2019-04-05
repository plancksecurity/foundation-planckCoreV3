# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE_REL := $(notdir $(CURDIR))

include Makefile.conf

ifneq ($(wildcard local.conf),)
    $(info ================================================)
    $(info Overrides in \`local.conf\` are used.)
    $(info ================================================)
endif

ifdef BUILD_CONFIG
    $(info ================================================)
    $(info Overrides in \`$(BUILD_CONFIG)\` are used.)
    $(info ================================================)
endif

all:
	$(MAKE) -C sync
	$(MAKE) -C asn.1
	$(MAKE) -C src

install: all
	$(MAKE) -C src install
	$(MAKE) -C asn.1 install

dbinstall: db
	$(MAKE) -C db install

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

.PHONY: tags
tags:
	$(MAKE) -C asn.1 tags
	$(MAKE) -C src tags

.PHONY: test
test: all
	$(MAKE) -C test test

.PHONY: package
package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 "$(HERE_REL)"

db:
	$(MAKE) -C db db
