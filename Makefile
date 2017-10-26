# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE_REL := $(notdir $(CURDIR))

include default.conf

.PHONY: all
all: _override_info
	$(MAKE) -C asn.1 generate
	$(MAKE) -C asn.1
	$(MAKE) -C sync
	$(MAKE) -C src all

.PHONY: install
install: all
	$(MAKE) -C src install
	$(MAKE) -C asn.1 install

.PHONY: uninstall
uninstall: _override_info
	$(MAKE) -C src uninstall
	$(MAKE) -C asn.1 uninstall

.PHONY: clean
clean: _override_info
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
db: _override_info
	$(MAKE) -C db db

.PHONY: _override_info
_override_info: _local_conf_info _build_config_info

.PHONY: _local_conf_info
_local_conf_info:
ifneq ($(wildcard local.conf),)
	@echo "================================================"
	@echo "Overrides in \`local.conf\` are used."
	@echo "================================================"
endif

.PHONY: _build_config_info
_build_config_info:
ifdef BUILD_CONFIG
	@echo "================================================"
	@echo "Overrides in \`$(BUILD_CONFIG)\` are used."
	@echo "================================================"
endif
