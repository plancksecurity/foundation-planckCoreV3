# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE:=$(CURDIR)

include ../Makefile.conf

LDFLAGS+= $(ETPAN_LIB) -L../asn.1
LDLIBS?=-letpan -lpEpEngine -lstdc++ -lasn1
ifeq ($(BUILD_FOR),Linux)
	LDLIBS+= -luuid
endif

ifeq ("$(OPENPGP)","NETPGP")
	LDLIBS+= -lnetpgp
endif

TARGET=pEpEngineTest

UNIT_TESTS_SOURCE=$(wildcard *_test.cc)
UNIT_TESTS=$(subst .cc,,$(UNIT_TESTS_SOURCE))
UNIT_TESTS_RUN=$(subst .cc,_run,$(UNIT_TESTS_SOURCE))

all: $(TARGET) $(UNIT_TESTS)

.PHONY: clean

# don't delete .o files!
.PRECIOUS: %.o

unexport GNUPGHOME;
TEST_HOME=$(HERE)/test_home
TEST_GNUPGHOME=$(TEST_HOME)/.gnupg

ifeq ($(shell which gpg2), )
    GPG_CMD = gpg
else
    GPG_CMD = gpg2
endif

ifeq ($(shell uname), Darwin)
    LIBPATH = DYLD_LIBRARY_PATH
    LLDB_BIN = /Applications/Xcode.app/Contents/Developer/usr/bin/lldb
else
    LIBPATH = LD_LIBRARY_PATH
    LLDB_BIN = lldb
endif

TEST_CMD_PFX = $(LIBPATH)=$(HOME)/lib:../src HOME=$(TEST_HOME)

test_home_: 
	-gpgconf --kill gpg-agent
	-HOME=$(TEST_HOME) gpgconf --kill gpg-agent
	-killall gpg-agent
	rm -rf $(TEST_HOME)
	mkdir -p $(TEST_GNUPGHOME)/private-keys-v1.d
	$(GPG_CMD) --import --batch --homedir $(TEST_GNUPGHOME) 0x*.asc *_sec.asc

clean:
	rm -f *.o $(TARGET) *.a *~ $(UNIT_TESTS) pep_Dokument_Titel.pdf msg4.asc
	rm -Rf *.dSYM $(TEST_HOME) pubring.gpg secring.gpg random_seed *.conf trustdb.gpg

test: pEpEngineTest test_home_
	$(TEST_CMD_PFX) ./pEpEngineTest

%_test : %_test.o test_util.o
	 $(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%_run : % test_home_
	$(TEST_CMD_PFX) ./$<

%_lldb : % test_home_
	$(TEST_CMD_PFX) $(LLDB_BIN) ./$<

%_valgrind : % test_home_
	$(TEST_CMD_PFX) valgrind --leak-check=yes ./$<

%_gdb : % test_home_
	$(TEST_CMD_PFX) gdb ./$<

unit_tests: $(UNIT_TESTS) $(UNIT_TESTS_RUN)

install:
	make -C .. install
