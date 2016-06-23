include ../Makefile.conf

CC?=g++ -std=gnu++11 -pthread
CXX?=g++ -std=gnu++11 -pthread
LD?=$(CXX)
LDFLAGS?=-L$(HOME)/local/lib
LDLIBS?=-letpan -lpEpEngine -lstdc++ -L../asn.1 -lasn1
CXXFLAGS?=-g -O0 -I../src -I../asn.1
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

clean:
	rm -f *.o $(TARGET) *.a *~ $(UNIT_TESTS) pep_Dokument_Titel.pdf msg4.asc
	rm -Rf *.dSYM

test: pEpEngineTest
	LD_LIBRARY_PATH=~/local/lib:../src ./pEpEngineTest

%_test_run : %_test
	LD_LIBRARY_PATH=~/local/lib:../src ./$<

%_test_lldb : %_test
	LD_LIBRARY_PATH=~/lib:../src lldb ./$<

unit_tests: $(UNIT_TESTS) $(UNIT_TESTS_RUN)

install:
	make -C .. install
