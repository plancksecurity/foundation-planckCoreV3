# Copyright 2019, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE:=$(CURDIR)

GTEST_SRC_DIR:=/usr/src/gtest
GTEST_INC_DIR:=$(GTEST_SRC_DIR)/include
GTEST_PL:=$(HOME)/src/gtest-parallel/gtest_parallel.py

include ../Makefile.conf # This should import changed values for the above from
                         # local.conf

SRCS:=$(wildcard src/*.cc) $(wildcard src/*/*.cc)
OBJS:=$(addsuffix .o,$(basename $(SRCS)))
DEPS:=$(OBJS:.o=.d)

LDFLAGS+= -L../asn.1 -L../src $(ETPAN_LIB) $(GTEST_LDFLAGS)

TARGET:=EngineTests

GTEST_SUITE_SYM:=test_suite_name

ifeq ($(shell grep -c $(GTEST_SUITE_SYM) $(GTEST_SRC_DIR)/src/gtest.cc),0)
    GTEST_SUITE_SYM=test_case_name
endif

CPPFLAGS+= -DGTEST_SUITE_SYM=$(GTEST_SUITE_SYM)

ifdef PEP_MIME
    LDLIBS+= -lpEpMIME
else
    LDLIBS+= -letpan
endif

LDLIBS+= -lstdc++ -lasn1

ifeq ($(BUILD_FOR),Linux)
    LDLIBS+= -luuid
endif

ifeq ($(OPENPGP),SEQUOIA)
    LDFLAGS+= $(SEQUOIA_LDFLAGS)
    LDLIBS+= $(SEQUOIA_LIB)
    CXXFLAGS+= $(SEQUOIA_CFLAGS) 
    CPPFLAGS+= -DUSE_SEQUOIA
    INC_FLAGS+= $(SEQUOIA_INC)
endif

ifdef SQLITE3_FROM_OS
    LDLIBS+= -lsqlite3
endif

CXXFLAGS:=$(filter-out -DNDEBUG,$(CXXFLAGS)) -I$(GTEST_INC_DIR)
CPPFLAGS:=$(filter-out -DNDEBUG,$(CPPFLAGS))

CXXFLAGS+= -I./src -I../src -I ../asn.1 -I../sync $(INC_FLAGS) -Wno-deprecated -Wno-unused-variable

EXTRA_LIB_PATHS=.:../src:
ifndef PEP_MIME
ifdef ETPAN_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(ETPAN_LIB)):
endif
endif

# Remove trailing ':'
EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS::=)

.PHONY: all clean test

all:
	make $(TARGET)

%.d: %.cc
	$(CXX) -MM $(CXXFLAGS) $(CPPFLAGS) $< | sed -e 's,\($*\)\.o[ :]*,\1.o $@: ,g' > $@

$(TARGET): $(OBJS)
	${CXX} ${CXXFLAGS} ${CPPFLAGS} ${LDFLAGS} -L${PREFIX}/lib -o $@ $^ ../src/libpEpEngine.a -lgtest -lgtest_main -lsequoia_openpgp_ffi $(LDLIBS)


test: all
	$(RM) -rf ./pEp_test_home/*
	$(TEST_DEBUGGER) GTEST_COLOR=no python3 $(GTEST_PL) --gtest_color=no ./$(TARGET)
clean:
	$(RM) $(TARGET) $(TARGET).o $(TARGET).d $(OBJS) $(notdir $(basename $(OBJS))) $(DEPS)
	$(RM) -rf ./pEp_test_home/*
# If only the goal 'clean' is given, do not generate and include the '%.d' files.¬
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPS)
endif
