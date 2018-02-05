# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE:=$(CURDIR)

include ../default.conf

TARGET=pEpEngineTest

unexport GNUPGHOME
TEST_HOME=$(HERE)test_home
TEST_GNUPGHOME=$(TEST_HOME)/gnupg

LDFLAGS+= $(ETPAN_LIB) -L../asn.1 -L../src
LDLIBS+= -letpan -lpEpEngine -lstdc++ -lasn1

ifeq ($(BUILD_FOR),Linux)
    LDLIBS+= -luuid
endif

ifeq ($(OPENPGP),NETPGP)
    LDLIBS+= -lnetpgp
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

TEST_CMD_PFX=$(LIBPATH)=$(EXTRA_LIB_PATHS) HOME=$(TEST_HOME) GNUPGHOME=$(TEST_GNUPGHOME)

UNIT_TESTS_SOURCE=$(wildcard *_test.cc)
UNIT_TESTS=$(subst .cc,,$(UNIT_TESTS_SOURCE))
UNIT_TESTS_RUN=$(subst .cc,_gdb,$(UNIT_TESTS_SOURCE))

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

.PHONY: all
all: $(TARGET) $(UNIT_TESTS)

# don't delete .o files!
.PRECIOUS: %.o

.PHONY: test_home_
test_home_: 
	-GNUPGHOME=$(TEST_GNUPGHOME) gpgconf --kill gpg-agent
	rm -rf $(TEST_HOME)
	mkdir -p $(TEST_GNUPGHOME)/private-keys-v1.d
	$(GPG_CMD) --import --batch --homedir $(TEST_GNUPGHOME) 0x*.asc *_sec.asc

.PHONY: clean
clean:
	rm -f *.o $(TARGET) *.a *~ $(UNIT_TESTS) pep_Dokument_Titel.pdf msg4.asc msg_encrypt_for_self.asc
	rm -Rf *.dSYM $(TEST_HOME) pubring.gpg secring.gpg random_seed *.conf trustdb.gpg

.PHONY: test
test: $(TARGET) test_home_
	$(TEST_CMD_PFX) ./$<

%_test : %_test.o test_util.o
	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@

%_run : % test_home_
	$(TEST_CMD_PFX) ./$<

%_lldb : % test_home_
	$(TEST_CMD_PFX) $(LLDB_BIN) ./$<

%_valgrind : % test_home_
	$(TEST_CMD_PFX) valgrind --leak-check=yes ./$<

%_gdb : % test_home_
	$(TEST_CMD_PFX) gdb ./$<

.PHONY: unit_tests
unit_tests: $(UNIT_TESTS) $(UNIT_TESTS_RUN)

.PHONY: compile
compile: $(UNIT_TESTS) $(TARGET)

# Installs the engine, not the test binaries
.PHONY: install
install:
	$(MAKE) -C .. install
