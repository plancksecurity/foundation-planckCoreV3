# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE:=$(CURDIR)

include ../Makefile.conf

# User's without python3 will skip the generated parts of the test suite. That's OK.
PY_ENV:=$(shell command -v python3 2> /dev/null)

TEST_HOME=$(HERE)/pEp_test_home

TARGET=TestDriver

SRCS:=$(wildcard src/*.cc) $(wildcard src/*/*.cc)
OBJS:=$(addsuffix .o,$(basename $(SRCS)))
DEPS:=$(OBJS:.o=.d)


LDFLAGS+= -L../asn.1 -L../src $(ETPAN_LIB) $(CPPUNIT_LIB)

ifeq ($(OPENPGP),GPG)
    LDFLAGS+= $(GPGME_LIB)
else ifeq ($(OPENPGP),NETPGP)
    LDFLAGS+= $(NETGPG_LIB)
endif


LDLIBS+= -letpan -lpEpEngine -lstdc++ -lasn1 -lcpptest

ifeq ($(BUILD_FOR),Linux)
    LDLIBS+= -luuid
endif

ifeq ($(OPENPGP),SEQUOIA)
    LDFLAGS+= $(SEQUOIA_LDFLAGS)
    LDLIBS+= $(SEQUOIA_LIB)
    CFLAGS+= $(SEQUOIA_CFLAGS) -DUSE_SEQUOIA
    INC_FLAGS+= $(SEQUOIA_INC)
endif

ifdef SQLITE3_FROM_OS
    LDLIBS+= -lsqlite3
endif

ifeq ($(OPENPGP),GPG)
    #LDLIBS+= -lgpgme
else ifeq ($(OPENPGP),NETPGP)
    LDLIBS+= -lnetpgp
    ifeq ($(BUILD_FOR),Linux)
        LDLIBS+= -ltre
    endif
endif


CXXFLAGS:=$(filter-out -DNDEBUG,$(CXXFLAGS))

# FIXME Possibly missing incdirs: ASN1C_INC
CXXFLAGS+= -I./include -I../sync $(CPPUNIT_INC) -Wno-deprecated

ifeq ($(OPENPGP),GPG)
    CXXFLAGS+= -DUSE_GPG $(GPGME_INC)
else ifeq ($(OPENPGP),NETPGP)
    CXXFLAGS+= -DUSE_NETPGP $(NETPGP_INC)
endif


EXTRA_LIB_PATHS=.:../src:
ifdef ETPAN_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(ETPAN_LIB)):
endif
ifdef GPGME_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(GPGME_LIB)):
endif
ifdef NETPGP_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(NETPGP_LIB)):
endif
ifdef CPPUNIT_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(CPPUNIT_LIB)):
endif

# Remove trailing ':'
EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS::=)

ifeq ($(BUILD_FOR),Darwin)
    LIBPATH=DYLD_LIBRARY_PATH
else
    LIBPATH=LD_LIBRARY_PATH
endif

# FIXME: this forces a path on execution which overrides system paths for
#        libraries like iconv and causes runtime errors.
#TEST_CMD_PFX=$(LIBPATH)=$(EXTRA_LIB_PATHS)
TEST_CMD_PFX=

.PHONY: all clean test

all:
	make .suitemaker
	make $(TARGET) .scripts
	touch .suitemaker

%.d: %.cc
	$(CXX) -MM $(CPPFLAGS) $(CXXFLAGS) $< | sed -e 's,\($*\)\.o[ :]*,\1.o $@: ,g' > $@

.suitemaker: src
ifndef PY_ENV
	@echo "WARNING: Can't find python3 - this is fine unless you're adding test suites. If so, please install python3."
else
ifndef EXCLUDE
	$(PY_ENV) gensuitemaker.py
else
	# Comma-separated list, no spaces
	$(PY_ENV) gensuitemaker.py --exclude=$(EXCLUDE)
endif
endif

$(TARGET): $(OBJS)
	$(LINK.cc) $(OBJS) $(LOADLIBES) $(LDLIBS) -o $@

.scripts:
ifdef PY_ENV
	$(PY_ENV) genscripts.py
	touch .scripts
endif

test: all
	$(TEST_CMD_PFX) $(TEST_DEBUGGER) ./$(TARGET)

clean:
	$(RM) $(TARGET) $(TARGET).o $(TARGET).d $(OBJS) $(notdir $(basename $(OBJS))) $(DEPS)
	$(RM) $(HERE)/*Tests msg_2.0.asc $(HERE)/pEp_test_home .scripts .suitemaker

# If only the goal 'clean' is given, do not generate and include the '%.d' files.¬
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPS)
endif
