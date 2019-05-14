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


# Build programs, libraries, documentation, etc..
.PHONY: all
all: allnodb db

# Like `all`, but without building the db
.PHONY: allnodb
allnodb: asn1 src sync

# Install what needs to be installed, copying the files from the package’s tree to system-wide directories.
.PHONY: install
install: all installnodb
	$(MAKE) -C db install

# Like `install`, but does install the db
.PHONY: installnodb
installnodb: allnodb
	$(MAKE) -C asn.1 install
	$(MAKE) -C src install

# The opposite of make install: erase the installed files. (This needs to be run from the same build tree that was installed.)
.PHONY: uninstall
uninstall:
	$(MAKE) -C asn.1 uninstall
	$(MAKE) -C db uninstall
	$(MAKE) -C src uninstall

# Erase from the build tree the files built by make all.
.PHONY: clean
clean:
	$(MAKE) -C asn.1 clean
	$(MAKE) -C db clean
	$(MAKE) -C src clean
	$(MAKE) -C sync clean
	$(MAKE) -C test clean

# Run the test suite.
.PHONY: check test
check test: all
	$(MAKE) -C test test

.PHONY: package
package: clean
	cd .. ; COPYFILE_DISABLE=true tar cjf pEpEngine.tar.bz2 "$(HERE_REL)"

.PHONY: tags
tags:
	$(MAKE) -C asn.1 tags
	$(MAKE) -C src tags

# You probably don't want to call any of the the targets below directly

.PHONY: asn1
asn1: sync
	$(MAKE) -C asn.1

.PHONY: db
db:
	$(MAKE) -C db

.PHONY: src
src: asn1 sync
	$(MAKE) -C src

.PHONY: sync
sync:
	$(MAKE) -C sync

