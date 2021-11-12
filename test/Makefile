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

ifeq ($(BUILD_ON),OS/390)
    OBJS+=../src/libpEpEngine.a
    OBJS+=/usr/lib/GSKCMS64.x
    OBJS+=/usr/lib/CSNPCA64.x
    OBJS+=/user/lev/lib/libetpan-no-mt.a
endif

#endif

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
    ifneq ($(BUILD_ON),OS/390)
        LDLIBS+= -letpan -lpEpEngine -lstdc++
    endif
endif

LDLIBS+= -lasn1

ifeq ($(BUILD_FOR),Linux)
    LDLIBS+= -luuid -lpthread
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

ifeq ($(OPENPGP),GPG)
    LDLIBS+= -lgpgme
else ifeq ($(OPENPGP),NETPGP)
    LDLIBS+=$(NETPGP_LIB)
    ifeq ($(BUILD_FOR),Linux)
        LDLIBS+= -ltre
    endif
endif

CXXFLAGS:=$(filter-out -DNDEBUG,$(CXXFLAGS))

# FIXME Possibly missing incdirs: ASN1C_INC
CXXFLAGS+= -I$(GTEST_INC_DIR) -I./src -I../sync $(INC_FLAGS) -Wno-deprecated -Wno-unused-variable

CXXFLAGS+= -I./src -I../src -I ../asn.1 -I../sync $(INC_FLAGS)
CXXFLAGS+= -Wno-deprecated -Wno-unused-variable

EXTRA_LIB_PATHS=.:../src:
ifndef PEP_MIME
ifdef ETPAN_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(ETPAN_LIB)):
endif
endif

# Remove trailing ':'
EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS::=)

ifeq ($(BUILD_FOR),Darwin)
    LIBPATH=DYLD_LIBRARY_PATH
else
    LIBPATH=LD_LIBRARY_PATH
endif

# The LIBPATH variable, whatever it is, should have the value of EXTRA_LIB_PATHS
# *prepended* to it -- without the rest of the path being lost.  This allows the
# user to use manually-installed version of some dependency libraries rather
# than system libraries.
TEST_CMD_PFX=$(LIBPATH)="$(EXTRA_LIB_PATHS):$$$(LIBPATH)"
ifeq ($(TEST_CMD_PFX),)
    TEST_CMD_PFX=
endif

.PHONY: all clean test

all:
	make $(TARGET)

%.d: %.cc
	$(CXX) -MM $(CXXFLAGS) $(CPPFLAGS) $< \
	| sed -e 's,\($*\)\.o[ :]*,\1.o $@: ,g' > $@

LDLIBS+=-lgtest -lgtest_main
ifeq ($(BUILD_ON),OS/390)
    LDLIBS+=-lzz
endif

ifeq ($(OPENPGP),SEQUOIA)
    LDLIBS+=-lsequoia_openpgp_ffi 
endif

$(TARGET): $(OBJS)
	${CXX} ${LDFLAGS} -L${PREFIX}/lib -o $@ $^ $(LDLIBS)

test: all
	$(RM) -rf ./pEp_test_home/*
	$(TEST_CMD_PFX) $(TEST_DEBUGGER) GTEST_COLOR=no python3 $(GTEST_PL) \
		--gtest_color=no ./$(TARGET)

clean:
	$(RM) $(TARGET) $(TARGET).o $(TARGET).d $(OBJS) \
		$(notdir $(basename $(OBJS))) $(DEPS)
	$(RM) -rf ./pEp_test_home/*

# If only the target 'clean' is given, do not generate and include the
# '%.d' files.¬
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPS)
endif
