# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE_REL := $(notdir $(CURDIR))

include Makefile.conf

ifneq ($(wildcard local.conf),)
    $(info ================================================)
    $(info Overrides in `local.conf` are used.)
    $(info ================================================)
endif

ifdef BUILD_CONFIG
    $(info ================================================)
    $(info Overrides in `$(BUILD_CONFIG)` are used.)
    $(info ================================================)
endif

BUILT_IN_MIME=

ifdef PEP_MIME
    BUILT_IN_MIME=pepmime
endif
    
.PHONY: all $(BUILT_IN_MIME) sync asn1 build install dbinstall uninstall clean tags test package db

build: $(BUILT_IN_MIME) asn1
	$(MAKE) -C src

all: build
# `make all` is not for tests, that's what `make test` is for
#	$(MAKE) -C test

pepmime: 
	$(MAKE) -C pEpMIME lib

sync:
	$(MAKE) -C sync

asn1: sync
	$(MAKE) -C asn.1


install: build
	$(MAKE) -C src install
	$(MAKE) -C asn.1 install
	$(MAKE) -C pEpMIME engine_install

beinstall:
	$(MAKE) -C src beinstall

dbinstall: db
	$(MAKE) -C db install

uninstall:
	$(MAKE) -C src uninstall
	$(MAKE) -C asn.1 uninstall

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C db clean
	$(MAKE) -C asn.1 clean
	$(MAKE) -C sync clean
	$(MAKE) -C build-android clean
ifdef PEP_MIME
	$(MAKE) -C pEpMIME clean
endif

tags:
	$(MAKE) -C asn.1 tags
	$(MAKE) -C src tags

test: all
	$(MAKE) -C test test

package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 "$(HERE_REL)"

db:
	$(MAKE) -C db db
