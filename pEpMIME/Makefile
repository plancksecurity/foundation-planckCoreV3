# This file is under GNU General Public License 3.0
# see LICENSE.txt

# The Engine build system in this directory used to copy pEpMIME source files
# from their source directory here, patch them, and compile them.  The process
# was complicated by a circular dependency: pEpMIME required the pEp Engine
# header.
# In order to avoid this complexity we now maintain pEpMIME directly in this
# directrory, as part of the pEp Engine.

.PHONY: lib all clean install test

include ../Makefile.conf

######### General #########
BUILD_ON:=$(shell uname)

# This variable specifies the platform that the engine should be cross-compiled for.
BUILD_FOR=$(BUILD_ON)

# Cross-compiling is currently not supported.
# Maybe you can hack something with `local.conf`.
ifneq ($(BUILD_ON),$(BUILD_FOR))
    $(error "I don't know how to build for $(BUILD_FOR) on $(BUILD_ON).")
endif

# MacOS needs -liconv, Linix don't.
ifeq ($(BUILD_FOR),Darwin)
    LDLIBS+= -liconv
endif

# Source file names
## This is useful to update: (cd pEpMIME; \ls -1 *.{cc,cxx,hh,hxx} 2> /dev/null)
LOCAL_PEPMIME_SRC:= \
  attachment.cc attachment.hh base64.cc base64.hh base64.hxx \
  bodygenerator.cc bodygenerator.hh bodyparser.cc bodyparser.hh fuzz.cc \
  header_generator.cc header_generator.hh headerparser.cc headerparser.hh \
  message.cc message.hh mime_headers.cc mime_headers.hh nfc.cc nfc.hh \
  nfc_sets.cc nfc_sets.hh nulllogger.cc nulllogger.hh parse_address.cc \
  parse_address.hh parse_timestamp.cc parse_timestamp.hh pEpEngine_mime.cc \
  pEpMIME.cc pEpMIME.hh pEpMIME_internal.cc pEpMIME_internal.hh \
  print_message.cc print_message.hh quoted_printable.cc quoted_printable.hh \
  quoted_printable.hxx rules.cc rules.hh string_case.hh to_utf8.cc to_utf8.hh
LOCAL_PEPMIME_TEST_SRC:= \
  unittest_address.cc unittest_base64.cc unittest_mime-12.cc unittest_mime.cc \
  unittest_nfc.cc unittest_qp.cc unittest_rule.cc unittest_stringcase.cc \
  unittest_subject.cc unittest_timestamp.cc unittest_toutf8.cc

all: lib

lib: libpEpMIME.a

# Copy the files to the local directory and change their engine header references to quoted references
%.hh : $(PEP_MIME_SRC)/%.hh
	cp -p $< $@
	$(SED) 's/#include <pEp\/\(.*\)>/#include "..\/src\/\1"/g' $@

%.cc : $(PEP_MIME_SRC)/%.cc
	cp -p $< $@
	$(SED) 's/#include <pEp\/\(.*\)>/#include "..\/src\/\1"/g' $@

%.hxx : $(PEP_MIME_SRC)/%.hxx
	cp -p $< $@
	$(SED) 's/#include <pEp\/\(.*\)>/#include "..\/src\/\1"/g' $@

LIB_OBJ=pEpMIME.o pEpMIME_internal.o rules.o bodyparser.o \
   attachment.o bodygenerator.o \
   headerparser.o parse_timestamp.o parse_address.o nulllogger.o \
   base64.o nfc.o mime_headers.o nfc_sets.o to_utf8.o quoted_printable.o \
   header_generator.o message.o pEpEngine_mime.o

libpEpMIME.a: $(LIB_OBJ)
	${AR} rcs $@ $^

#%.o : %.cc %.hh
#	${CXX} ${CXXFLAGS} ${CPPFLAGS} -I${PREFIX}/include -o $@ -c $<
#%.o : %.cc
#	${CXX} ${CXXFLAGS} ${CPPFLAGS} -I${PREFIX}/include -o $@ -c $<
%.o : %.cc %.hh
	${CXX} ${CXXFLAGS} ${CPPFLAGS} -o $@ -c $<
#%.o : %.cc
#	${CXX} ${CXXFLAGS} ${CPPFLAGS} -o $@ -c $<

clean:
	rm -vf *.o *.a

srcclean:
	rm *.cc *.hh *.hxx

#install: lib
#	mkdir -p "$(DESTDIR)$(PREFIX)/lib/"
#	cp -v libpEpMIME.a $(DESTDIR)$(PREFIX)/lib

#uninstall:
#	rm $(DESTDIR)$(PREFIX)/lib/libpEpMIME.a

