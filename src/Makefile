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
        LDLIBS+= -lz -liconv
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

.PHONY: objects clean install uninstall beinstall

objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	$(AR) -rc $@ $^

clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~
	rm -Rf $(TARGET).dSYM
	rm -f KeySync_fsm.* Sync_actions.c Sync_event.* Sync_func.* Sync_impl.* sync_codec.* distribution_codec.*

install: $(TARGET)
	mkdir -p "$(PREFIX)/lib/"
	cp $< $(PREFIX)/lib/

beinstall: install
	cp platform*.h $(PREFIX)/include/pEp/

uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)
	rm -rf $(PREFIX)/include/pEp

tags: $(wildcard *.c) $(wildcard *.h)
	ctags --sort=yes *.c *.h
