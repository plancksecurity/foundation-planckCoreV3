
# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../default.conf

PY_ENV := $(shell command -v python3 2> /dev/null)

HERE:=$(CURDIR)
TEST_HOME=$(HERE)/pEp_test_home

TARGET=TestDriver

SRCS := $(wildcard src/*.cc) $(wildcard src/*/*.cc)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)

INC_DIRS := ./include /usr/local/include ../src ../sync ../asn.1
INC_FLAGS := $(addprefix -I,$(INC_DIRS)) $(GPGME_INC) $(CPPUNIT_INC)

LDFLAGS += -L/usr/local/lib
CFLAGS += -Wno-deprecated
CXXFLAGS += -Wno-deprecated
CFLAGS:=$(filter-out -Wall,$(CFLAGS))

LDFLAGS+= $(ETPAN_LIB) $(CPPUNIT_LIB) -L../asn.1 -L../src
LDLIBS+= -letpan -lpEpEngine -lstdc++ -lasn1

ifeq ($(BUILD_FOR),Linux)
	LDLIBS+= -luuid
endif

ifeq ($(OPENPGP),NETPGP)
	LDLIBS+= -lnetpgp
	CFLAGS+= -DUSE_NETPGP
ifeq ($(BUILD_FOR),Linux)
	LDLIBS+= -ltre
endif
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

ifeq ($(shell uname),Darwin)
	LIBPATH=DYLD_LIBRARY_PATH
	LLDB_BIN=/Applications/Xcode.app/Contents/Developer/usr/bin/lldb
else
	LIBPATH=LD_LIBRARY_PATH
	LLDB_BIN=lldb
endif

LDLIBS+= -lcpptest


# Create a list of the extra library paths for the loader. I do not assume that the engine (and its dependencies) are installed for testing.
# Note that += can not be used here, as it changes the amount of whitespace
EXTRA_LIB_PATHS=../src:
ifdef ETPAN_LIB
	EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(ETPAN_LIB)):
endif
ifdef GPGME_LIB
	EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(GPGME_LIB)):
endif
ifdef NETPGP_LIB
	EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(NETPGP_LIB)):
endif

# Remove trailing ':'
EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS::=)

CFLAGS:=$(filter-out -DNDEBUG,$(CFLAGS))
ifneq ($(MAKECMDGOALS),clean)
	ifneq (,$(findstring -DNDEBUG,$(CFLAGS)))
		$(error The macro NDEBUG must not be defined for test compilation.)
	endif
endif

CXXFLAGS:=$(filter-out -DNDEBUG,$(CXXFLAGS))
ifneq ($(MAKECMDGOALS),clean)
	ifneq (,$(findstring -DNDEBUG,$(CXXFLAGS)))
		$(error The macro NDEBUG must not be defined for test compilation.)
	endif
endif

CPPFLAGS += $(INC_FLAGS) -MMD -MP

all: suitemaker $(TARGET) test_home_ scripts
	
%.o: %.cc
	$(CXX) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

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
		
.PHONY: test_home_
test_home_: 
	

.PHONY: scripts
scripts: 
ifdef PY_ENV
	$(PY_ENV) genscripts.py
endif

.PHONY: test
test: all
	ulimit -n 20000; $(TEST_DEBUGGER) ./$(TARGET)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)
	$(RM) $(HERE)/*Tests msg_2.0.asc



-include $(DEPS)
 
