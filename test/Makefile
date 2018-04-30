
# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../default.conf

HERE:=$(CURDIR)
TEST_HOME=$(HERE)pEp_test_home

TARGET=TestDriver

SRC_DIRS := ./src ./src/util ./src/engine_tests
SRCS := src/EngineTestSuite.cc src/EngineTestIndividualSuite.cc src/EngineTestSessionSuite.cc $(wildcard src/*/*.cc) src/SuiteMaker.cc src/TestDriver.cc
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)

INC_DIRS := ./include /usr/local/include #$(shell find $(SRC_DIRS) -type d) 
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

LDFLAGS += -L/usr/local/lib

CFLAGS += -Wno-deprecated
CXXFLAGS += -Wno-deprecated

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

LDLIBS += -lcpptest


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

$(TARGET): $(OBJS)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) $(OBJS) -o $@ $(LOADLIBES) $(LDLIBS)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)


# 
# TEST_CMD_PFX=$(LIBPATH)=$(EXTRA_LIB_PATHS) #HOME=$(TEST_HOME) GNUPGHOME=$(TEST_GNUPGHOME)
# 
# 
# CFLAGS:=$(filter-out -DNDEBUG,$(CFLAGS))
# ifneq ($(MAKECMDGOALS),clean)
# 	ifneq (,$(findstring -DNDEBUG,$(CFLAGS)))
# 		$(error The macro NDEBUG must not be defined for test compilation.)
# 	endif
# endif
# 
# CXXFLAGS:=$(filter-out -DNDEBUG,$(CXXFLAGS))
# ifneq ($(MAKECMDGOALS),clean)
# 	ifneq (,$(findstring -DNDEBUG,$(CXXFLAGS)))
# 		$(error The macro NDEBUG must not be defined for test compilation.)
# 	endif
# endif
# 
# # .PHONY: all
# # all: main
# 
# # don't delete .o files!
# .PRECIOUS: %.o
# 
# 
# SRC_DIRS ?= ./src
# 
# SRCS := $(wildcard src/*.cc) $(wildcard src/*/*.cc)
# OBJS := $(addsuffix .o,$(basename $(SRCS)))
# DEPS := $(OBJS:.o=.d)
# 
# CPPFLAGS += -I./include -MMD -MP
# 
# #	$(CC) $(LDFLAGS) $(OBJS) -o $@ $(LOADLIBES) $(LDLIBS)
# $(TARGET): $(OBJS)
# 	$(CXX) $(CXXFLAGS) $^ $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@
# 
# 
# .PHONY: test_home_
# test_home_: 
# 	mkdir -p $(TEST_HOME)
# 
# # .PHONY: clean
# # clean:
# # 	rm -f *.o $(TARGET) *.a *~ $(UNIT_TESTS) msg4.asc msg_encrypt_for_self.asc
# 
# 
# .PHONY: clean
# clean:
# 	$(RM) $(TARGET) $(OBJS) $(DEPS)
# 
# -include $(DEPS)
# 
# # .PHONY: main
# # main: TestDriver
# # 	
# # TestDriver : src/TestDriver
# # 	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) $(LDLIBS) $(TESTOBJ) $(SUITEOBJ) -o TestDriver
# # 
# # .PHONY: testfiles
# # testfiles : $(TESTOBJ)
# # 	$(CXX) -c $(CXXFLAGS) $^ $(LDFLAGS) $(LDLIBS)
# # 
# # .PHONY: suitefiles	
# # suitefiles : $(SUITEOBJ)
# # 	$(CXX) -c $(CXXFLAGS) $^ $(LDFLAGS) $(LDLIBS)
# #  
# # # %_test : %_test.o test_util.o
# # # 	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@
# # # 
# # # %_run : % test_home_
# # # 	$(TEST_CMD_PFX) ./$<
# # # 
# # # %_lldb : % test_home_
# # # 	$(TEST_CMD_PFX) $(LLDB_BIN) ./$<
# # # 
# # # %_valgrind : % test_home_
# # # 	$(TEST_CMD_PFX) valgrind --leak-check=yes ./$<
# # # 
# # # %_gdb : % test_home_
# # # 	$(TEST_CMD_PFX) gdb ./$<
# # 
# # # .PHONY: unit_tests
# # # unit_tests: $(UNIT_TESTS) $(UNIT_TESTS_RUN)
# # 
# # # .PHONY: compile
# # # compile: $(UNIT_TESTS) $(TARGET)
# # 
# # # Installs the engine, not the test binaries
# # .PHONY: install
# # install:
# # 	$(MAKE) -C .. install
