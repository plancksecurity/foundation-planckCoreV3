# Copyright 2019, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

HERE:=$(CURDIR)

# Presumably can be changed in local.conf by putting this here?
GTEST_DIR:=googletest/googletest
GTEST_PL_DIR:=googletest/gtest-parallel

include ../Makefile.conf

SRCS:=$(wildcard src/*.cc) $(wildcard src/*/*.cc)
OBJS:=$(addsuffix .o,$(basename $(SRCS)))
DEPS:=$(OBJS:.o=.d)

LDFLAGS+= -L../asn.1 -L../src $(ETPAN_LIB) $(CPPUNIT_LIB)

TARGET:=EngineTests 

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

CXXFLAGS:=$(filter-out -DNDEBUG,$(CXXFLAGS))

# FIXME Possibly missing incdirs: ASN1C_INC
CXXFLAGS+= -I./include -I../sync $(CPPUNIT_INC) $(INC_FLAGS) -Wno-deprecated

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
ifdef CPPUNIT_LIB
    EXTRA_LIB_PATHS:=$(EXTRA_LIB_PATHS)$(patsubst -L%,%,$(CPPUNIT_LIB)):
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

$(TARGET): $(OBJS) gtest-all.o gtest_main.o
#	$(LINK.cc) $(OBJS) $(LOADLIBES) $(LDLIBS) -o $@
	${CXX} ${LDFLAGS} -L${PREFIX}/lib -o $@ $^ -lpEpEngine $(LDLIBS)

gtest-all.o: $(GTEST_DIR)/src/gtest-all.cc
	${CXX} ${CXXFLAGS} $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -isystem $(GTEST_DIR)/include -o $@ -c $<

gtest_main.o: $(GTEST_DIR)/src/gtest_main.cc
	${CXX} ${CXXFLAGS} $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -isystem $(GTEST_DIR)/include -o $@ -c $<

test: all
	$(TEST_CMD_PFX) $(TEST_DEBUGGER) python3 $(GTEST_PL_DIR)/gtest_parallel.py ./$(TARGET)

clean:
	$(RM) $(TARGET) $(TARGET).o $(TARGET).d $(OBJS) $(notdir $(basename $(OBJS))) $(DEPS)
	$(RM) gtest_main.o gtest-all.o
# If only the goal 'clean' is given, do not generate and include the '%.d' files.¬
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPS)
endif
