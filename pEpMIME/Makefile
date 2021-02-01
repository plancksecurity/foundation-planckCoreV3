# This file is under GNU General Public License 3.0
# see LICENSE.txt

##################################################################################
# This is a modified Makefile based on that in the libpEpMIME repository.
# THEY ARE NOT INTERCHANGEABLE. This is SPECIFICALLY for the pEp engine and
# is only for the built-in variant of the compiler.
#
# Note that this is the only supported way of including pEpMIME within the engine.
#
# If additional object files are added to the repository object requirements, they
# will have to be included here specifically.
##################################################################################

.PHONY: mimesrc lib all clean install test

include ../Makefile.conf

######### General #########
BUILD_ON:=$(shell uname)

# This variable specifies the platform that the engine should be cross-compiled for.
BUILD_FOR=$(BUILD_ON)

# Cross-compiling is currently not supported.
# Maybe you can hack something with `local.conf`.
ifneq ($(BUILD_ON),$(BUILD_FOR))
    $(error I don't know how to build for $(BUILD_FOR) on $(BUILD_ON).)
endif

# MacOS needs -liconv, Linix don't.
ifeq ($(BUILD_FOR),Darwin)
    LDLIBS+= -liconv
endif

PEPMIME_SRC_FILES:= $(wildcard $(PEP_MIME_SRC)/*.cc) $(wildcard $(PEP_MIME_SRC)/*.hh) $(wildcard $(PEP_MIME_SRC)/*.hxx)
LOCAL_PEPMIME_SRC:= $(subst $(PEP_MIME_SRC)/,,$(PEPMIME_SRC_FILES))

#$(error $(PEP_MIME_SRC) BOB $(PEPMIME_SRC_FILES) ********************   $(LOCAL_PEPMIME_SRC))

all: lib

lib: mimesrc libpEpMIME.a

mimesrc: ${LOCAL_PEPMIME_SRC}

%.hh : $(PEP_MIME_SRC)/%.hh
	cp -p $< $@
	sed -i '' 's/#include <pEp\/\(.*\)>/#include "..\/src\/\1"/g' $@

%.cc : $(PEP_MIME_SRC)/%.cc
	cp -p $< $@
	sed -i '' 's/#include <pEp\/\(.*\)>/#include "..\/src\/\1"/g' $@

%.hxx : $(PEP_MIME_SRC)/%.hxx
	cp -p $< $@
	sed -i '' 's/#include <pEp\/\(.*\)>/#include "..\/src\/\1"/g' $@

LIB_OBJ=pEpMIME.o pEpMIME_internal.o rules.o bodyparser.o \
   attachment.o bodygenerator.o \
   headerparser.o parse_timestamp.o parse_address.o nulllogger.o \
   base64.o nfc.o mime_headers.o nfc_sets.o to_utf8.o quoted_printable.o \
   header_generator.o message.o pEpEngine_mime.o

libpEpMIME.a: $(LIB_OBJ)
	${AR} rcs $@ $^

%.o : %.cc %.hh
	${CXX} ${CXXFLAGS} -I${PREFIX}/include -o $@ -c $<

%.o : %.cc
	${CXX} ${CXXFLAGS} -I${PREFIX}/include -o $@ -c $<

clean:
	rm -vf *.o *.a

srcclean:
	rm *.cc *.hh *.hxx

install: lib 
	mkdir -p "$(PREFIX)/lib/"
	cp -v libpEpMIME.a $(PREFIX)/lib

uninstall:
	rm $(PREFIX)/lib/libpEpMIME.a

