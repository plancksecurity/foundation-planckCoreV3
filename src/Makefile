# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../Makefile.conf

ifdef PER_USER_DIRECTORY
	EXTRA_MACROS+= -DPER_USER_DIRECTORY=$(PER_USER_DIRECTORY)
endif

ifdef PER_MACHINE_DIRECTORY
	EXTRA_MACROS+= -DPER_MACHINE_DIRECTORY=\"$(PER_MACHINE_DIRECTORY)\"
endif

CFLAGS+= $(ETPAN_INC) $(PEP_MIME_INC) -I../asn.1 $(EXTRA_MACROS)
LDFLAGS+= $(ETPAN_LIB) $(PEP_MIME_LIB) -L../asn.1 -shared
LDLIBS+= -lc -lasn1
NO_SOURCE=

ifndef PEP_MIME
LDLIBS+= -letpan
else
LDLIBS+= -lpEpMIME
NO_SOURCE+= etpan_mime.c
endif

ifeq ($(BUILD_ON),Darwin)
    ifeq ($(BUILD_FOR),Darwin)
        CFLAGS+= -DSQLITE_THREADSAFE=1
        LDLIBS+= -lz -liconv -mmacosx-version-min=10.10
    else
        $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else ifeq ($(BUILD_ON),Linux)
    ifeq ($(BUILD_FOR),Linux)
        CFLAGS+= -DSQLITE_THREADSAFE=1 -D_GNU_SOURCE
        LDLIBS+= -ldl -luuid
    else
        $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else
    $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ifdef SQLITE3_FROM_OS
    NO_SOURCE+= sqlite3.c
    CFLAGS+= -DSQLITE3_FROM_OS
    LDLIBS+= -lsqlite3
endif

ifeq ($(OPENPGP),SEQUOIA)
    CFLAGS+= -DUSE_SEQUOIA $(SEQUOIA_CFLAGS) $(SEQUOIA_INC)
    LDFLAGS+= $(SEQUOIA_LDFLAGS)
    LDLIBS+= $(SEQUOIA_LIB)
else
    $(error Unknown OpenPGP library: $(OPENPGP))
endif

ALL_SOURCE=$(filter-out $(NO_SOURCE),$(wildcard *.c))
DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

all: $(TARGET)

-include Makefile.protocols

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

# If only the goal 'clean' is given, do not generate and include the '%.d' files.
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPENDS)
endif

$(TARGET): libpEpEngine.a
	$(CC) $(CFLAGS) $(ALL_OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: objects clean install_headers install uninstall beinstall

objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	$(AR) -rc $@ $^

clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~
	rm -Rf $(TARGET).dSYM
	rm -f KeySync_fsm.* Sync_actions.c Sync_event.* Sync_func.* Sync_impl.* sync_codec.* distribution_codec.*

# CAVEAT:
# install_headers is needed for building pEp MIME

install_headers: $(TARGET)
	mkdir -p $(PREFIX)/include/pEp
	cp pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h \
	   timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h \
	   cryptotech.h sync_api.h blacklist.h pEp_string.h openpgp_compat.h \
	   labeled_int_list.h key_reset.h base64.h sync_codec.h distribution_codec.h \
	   status_to_string.h aux_mime_msg.h keyreset_command.h platform.h platform_unix.h ../asn.1/*.h \
 	   $(PREFIX)/include/pEp/

install: $(TARGET) install_headers
	mkdir -p "$(PREFIX)/lib/"
	cp -v $< $(PREFIX)/lib/
	cp -v libpEpEngine.a $(PREFIX)/lib/

beinstall: install
	cp platform*.h $(PREFIX)/include/pEp/

uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)
	rm -rf $(PREFIX)/include/pEp

tags: $(wildcard *.c) $(wildcard *.h)
	ctags --sort=yes *.c *.h

