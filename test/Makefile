
# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../default.conf

# I tend to not use spacing around assignment operators in Make. Sometimes weird things happen.
# Also -- this is very much a matter of taste -- my python scripts all have '#!/usr/bin/env python3' as the first line, and it's the user's job for there to always be an appropriate python3. I wouldn't add any business logic in the makefile regarding finding the python interpreter, if I just run my own python scripts.
PY_ENV := $(shell command -v python3 2> /dev/null)

# Since you 'include' before evaluating CURDIR, I think it's possible that CURDIR does not have the value you think it might have. Yes, make is awkward.
HERE:=$(CURDIR)
TEST_HOME=$(HERE)/pEp_test_home

TARGET=TestDriver

SRCS := $(wildcard src/*.cc) $(wildcard src/*/*.cc)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)

# Using '/usr/local/include' is very much a "works on my machine" solution to the problem. Either, the compiler search paths are enough, otherwise define a BLA_INC and BLA_LIB path to make clear to other developers what you are looking for outside the standard paths.
INC_DIRS := ./include /usr/local/include ../src ../sync ../asn.1
# Whoa dude... addprefix is brilliant. Why didn't I find this before!? This could make setting all the *_INC and *_LIB so much nicer!
INC_FLAGS := $(addprefix -I,$(INC_DIRS)) $(GPGME_INC) $(CPPUNIT_INC)

# '+=' is a magic assignment operators. It ensures that there is exactly one space between the old value and the suffix. Yes, this means it might strip spaces. At any rate, there is no need to add a space after the operator.
LDFLAGS += -L/usr/local/lib

# For setting both C and C++ compiler flags, there is CPPFLAGS
CFLAGS += -Wno-deprecated
CXXFLAGS += -Wno-deprecated
CFLAGS:=$(filter-out -Wall,$(CFLAGS))

LDFLAGS+= $(ETPAN_LIB) $(CPPUNIT_LIB) -L../asn.1 -L../src
LDLIBS+= -letpan -lpEpEngine -lstdc++ -lasn1

# Caution: you're using tab to indent here, but none of the lines from here to 60 are recipes. Indentation should be done with spaces. This only works because Make is such a gratious tool. (Yeah, right...)
ifeq ($(BUILD_FOR),Linux)
	LDLIBS+= -luuid
endif

ifeq ($(OPENPGP),NETPGP)
	LDLIBS+= -lnetpgp
	CFLAGS+= -DUSE_NETPGP
ifeq ($(BUILD_FOR),Linux)
	LDLIBS+= -ltre
endif
endif

ifdef SQLITE3_FROM_OS
	LDLIBS+= -lsqlite3
endif

# Looks like both LIBPATH and LLDB_BIN aren't needed any more.
ifeq ($(shell uname),Darwin)
	LIBPATH=DYLD_LIBRARY_PATH
	LLDB_BIN=/Applications/Xcode.app/Contents/Developer/usr/bin/lldb
else
	LIBPATH=LD_LIBRARY_PATH
	LLDB_BIN=lldb
endif

LDLIBS+= -lcpptest

# Probably everything from here to 81 is not needed any more either...
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

# Forgot the phony for all?
all: suitemaker $(TARGET) test_home_ scripts
	
# There is probably a built-in rules that makes this redundant. Unless we're not using '.cc' or 'CPPFLAGS' as is canon in GNU Make land.
%.o: %.cc
	$(CXX) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: suitemaker
suitemaker:
ifndef PY_ENV
	@echo "WARNING: Can't find python3 - this is fine unless you're adding test suites. If so, please install python3."
else
ifndef EXCLUDE
	$(PY_ENV) gensuitemaker.py
else
	# Comma-separated list, no spaces
	$(PY_ENV) gensuitemaker.py --exclude=$(EXCLUDE)
endif
endif
		
# This target does nothing.
.PHONY: test_home_
test_home_: 
	

# So, if there is no python, then 'scripts' will trivially be up to date, because there is no recipe associated with this rule. That's probably not what you want.
.PHONY: scripts
scripts: 
ifdef PY_ENV
	$(PY_ENV) genscripts.py
endif

# Ah, yes, here it is. Finally someone tripped over me introducing both Makefile.conf and default.conf. TEST_DEBUGGER is documented in one, but not the other Makefile. Yeah, I should clean this up, otherwise every time a new knob is added, it will only appear in either Makefile.conf or default.conf.
.PHONY: test
test: all
	$(TEST_DEBUGGER) ./$(TARGET)
	
.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)
	$(RM) $(HERE)/*Tests msg_2.0.asc



# You know, I think we have this "compiler generates Makefiles" pattern in another makefile in the engine, but there it looks completly different. From reading just this makefile: are you sure, the compiler generated Makefiles are actually every generated? You don't have DEPS as a prerequisite anywhere. Is there some built-in rule that has %.d as a prerequisite? Without further investigation I am not convinced the %.d files are ever generated...
-include $(DEPS)
 
