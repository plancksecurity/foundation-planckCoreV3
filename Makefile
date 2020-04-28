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

.PHONY: all sync asn1 build install install_headers dbinstall uninstall clean tags test package db

build: asn1
	$(MAKE) -C src

all: build
# `make all` is not for tests, that's what `make test` is for
#	$(MAKE) -C test

sync:
	$(MAKE) -C sync

asn1: sync
	$(MAKE) -C asn.1

install: build install_headers
	$(MAKE) -C src install
	$(MAKE) -C asn.1 install

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

tags:
	$(MAKE) -C asn.1 tags
	$(MAKE) -C src tags

test: all
	$(MAKE) -C test test

# CAVEAT:
# install_headers is needed for building pEp MIME

install_headers:
	$(MAKE) -C sync 
	cd asn.1; $(MAKE) gen_asn1; cd ..
	mkdir -p $(PREFIX)/include/pEp
	cd src; cp pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h \
	   timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h \
	   cryptotech.h sync_api.h blacklist.h pEp_string.h openpgp_compat.h mime.h \
	   labeled_int_list.h key_reset.h base64.h sync_codec.h distribution_codec.h \
	   status_to_string.h aux_mime_msg.h keyreset_command.h platform.h platform_unix.h ../asn.1/*.h \
 	   $(PREFIX)/include/pEp/

package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 "$(HERE_REL)"

db:
	$(MAKE) -C db db
