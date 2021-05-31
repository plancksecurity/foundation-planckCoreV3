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

ifeq ($(shell grep -qc $(GTEST_SUITE_SYM) $(GTEST_SRC_DIR)/src/gtest.cc 2>/dev/null),0)
    GTEST_SUITE_SYM=test_case_name
endif

CXXFLAGS+= -DGTEST_SUITE_SYM=$(GTEST_SUITE_SYM)

ifeq ($(OPENPGP),GPG)
    LDFLAGS+= $(GPGME_LIB)
else ifeq ($(OPENPGP),NETPGP)
    LDFLAGS+= $(NETGPG_LIB)
endif

LDLIBS+= -letpan -lpEpEngine -lstdc++ -lasn1

ifeq ($(BUILD_FOR),Linux)
    LDLIBS+= -luuid
endif

ifeq ($(OPENPGP),SEQUOIA)
    LDFLAGS+= $(SEQUOIA_LDFLAGS)
    LDLIBS+= $(SEQUOIA_LIB)
    CXXFLAGS+= $(SEQUOIA_CFLAGS) -DUSE_SEQUOIA
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

CXXFLAGS:=-I$(GTEST_INC_DIR) $(filter-out -DNDEBUG,$(CXXFLAGS))

# FIXME Possibly missing incdirs: ASN1C_INC
CXXFLAGS+= -I./src -I../sync $(INC_FLAGS) -Wno-deprecated -Wno-unused-variable

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
	make $(TARGET)

%.d: %.cc
	$(CXX) -MM $(CPPFLAGS) $(CXXFLAGS) $< | sed -e 's,\($*\)\.o[ :]*,\1.o $@: ,g' > $@

$(TARGET): $(OBJS)
	${CXX} ${LDFLAGS} -L${PREFIX}/lib -o $@ $^ -lpEpEngine -lgtest -lgtest_main -lsequoia_openpgp_ffi $(LDLIBS)


test: all
	$(RM) -rf ./pEp_test_home/*
	$(TEST_CMD_PFX) $(TEST_DEBUGGER) GTEST_COLOR=no python3 $(GTEST_PL) --gtest_color=no ./$(TARGET)
clean:
	$(RM) $(TARGET) $(TARGET).o $(TARGET).d $(OBJS) $(notdir $(basename $(OBJS))) $(DEPS)
	$(RM) -rf ./pEp_test_home/*
# If only the goal 'clean' is given, do not generate and include the '%.d' files.¬
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPS)
endif
