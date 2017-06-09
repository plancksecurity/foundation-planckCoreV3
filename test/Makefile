
# This file is under GNU General Public License 3.0
# see LICENSE.txt

HERE := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

include ../Makefile.conf

CC?=g++ -std=gnu++11 -pthread
CXX?=g++ -std=gnu++11 -pthread
LD?=$(CXX)
LDFLAGS?=-L$(HOME)/lib
LDLIBS?=-letpan -lpEpEngine -lstdc++ -L../asn.1 -lasn1
ifeq ($(BUILD_FOR),Linux)
	LDLIBS+= -luuid
endif
CXXFLAGS?=-std=c++11 -g -O0 -I../src -I../asn.1
# CXXFLAGS=-O3 -DNDEBUG

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
TEST_HOME_SKEL=$(TEST_HOME)_skel
TEST_GNUPGHOME_SKEL=$(TEST_HOME)_skel/.gnupg

ifeq ($(shell uname), Darwin)
    LIBPATH = DYLD_LIBRARY_PATH
else
    LIBPATH = LD_LIBRARY_PATH
endif

TEST_CMD_PFX = $(LIBPATH)=$(HOME)/lib:../src HOME=$(TEST_HOME)

test_home_skel:
	mkdir -p test_home_skel
	-cat 0x*.asc *_sec.asc | gpg2 --import --homedir $(TEST_GNUPGHOME_SKEL)
	$(TEST_CMD_CLEAN)

test_home_: test_home_skel
	rm -rf test_home
	cp -a test_home_skel test_home

clean:
	rm -f *.o $(TARGET) *.a *~ $(UNIT_TESTS) pep_Dokument_Titel.pdf msg4.asc
	rm -Rf *.dSYM test_home test_home_skel pubring.gpg secring.gpg random_seed *.conf trustdb.gpg

test: pEpEngineTest test_home_
	$(TEST_CMD_PFX) ./pEpEngineTest

%_test : %_test.o test_util.o
	 $(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%_run : % test_home_
	$(TEST_CMD_PFX) ./$<

%_lldb : % test_home_
	$(TEST_CMD_PFX) lldb ./$<

%_valgrind : % test_home_
	$(TEST_CMD_PFX) valgrind --leak-check=yes ./$<

%_gdb : % test_home_
	$(TEST_CMD_PFX) gdb ./$<

unit_tests: $(UNIT_TESTS) $(UNIT_TESTS_RUN)

install:
	make -C .. install
