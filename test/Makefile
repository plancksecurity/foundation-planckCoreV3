include ../Makefile.conf

CC=g++ -std=gnu++11 -pthread
CXX=g++ -std=gnu++11 -pthread
LD=$(CXX)
LDFLAGS=-L$(HOME)/lib -lpEpEngine -lstdc++
CXXFLAGS=-g -O0 -I../src
# CXXFLAGS=-O3 -DNDEBUG

TARGET=pEpEngineTest

UNIT_TESTS_SOURCE=$(wildcard *_test.cc)
UNIT_TESTS=$(subst .cc,,$(UNIT_TESTS_SOURCE))

all: $(TARGET) $(UNIT_TESTS)

.PHONY: clean

clean:
	rm -f *.o $(TARGET) *.a *~ $(UNIT_TESTS)

test: pEpEngineTest
	LD_LIBRARY_PATH=~/lib:../src ./pEpEngineTest

unit_tests: $(UNIT_TESTS)
	for t in ./*_test ; do \
		LD_LIBRARY_PATH=~/lib:../src $$t ; \
	done
