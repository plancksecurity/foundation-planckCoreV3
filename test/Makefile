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


.PHONY: all
all: suitemaker $(TARGET) scripts

%.d: %.cc
	$(CXX) -MM $(CPPFLAGS) $(CXXFLAGS) $< | sed -e 's,\($*\)\.o[ :]*,\1.o $@: ,g' > $@

$(TARGET): $(OBJS)
# This should actually be done with a built-in rule
#	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: suitemaker
suitemaker:
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

.PHONY: scripts
scripts:
ifdef PY_ENV
	$(PY_ENV) genscripts.py
endif

.PHONY: test
test: all
	$(TEST_DEBUGGER) ./$(TARGET)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)
	$(RM) $(HERE)/*Tests msg_2.0.asc

# If only the goal 'clean' is given, do not generate and include the '%.d' files.¬
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPS)
endif
