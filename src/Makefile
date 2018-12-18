# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../default.conf

CFLAGS+= $(ETPAN_INC) -I../asn.1 -DSYSTEM_DB=\"$(SYSTEM_DB)\" $(EXTRA_MACROS)
LDFLAGS+= $(ETPAN_LIB) -L../asn.1 -shared
LDLIBS+= -lc -letpan -lasn1
NO_SOURCE=

ifeq ($(BUILD_ON),Darwin)
    ifeq ($(BUILD_FOR),Darwin)
        CFLAGS+= -DSQLITE_THREADSAFE=1
        LDLIBS+= -lz -liconv
    else
        $(error I don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else ifeq ($(BUILD_ON),Linux)
    ifeq ($(BUILD_FOR),Linux)
        CFLAGS+= -DSQLITE_THREADSAFE=1 -D_GNU_SOURCE
        LDLIBS+= -ldl -luuid
    else
        $(error I don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else
    $(error I don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ifdef SQLITE3_FROM_OS
    NO_SOURCE+= sqlite3.c
    CFLAGS+= -DSQLITE3_FROM_OS
    LDLIBS+= -lsqlite3
endif

ifeq ($(OPENPGP),GPG)
    NO_SOURCE+= pgp_netpgp.c
    CFLAGS+= -DUSE_GPG $(GPGME_INC) -DLIBGPGME=\"$(LIBGPGME)\"
    LDFLAGS+= $(GPGME_LIB)
    # No extra LDLIBS are needed here, because GPGME is dynamically loaded
else ifeq ($(OPENPGP),NETPGP)
    NO_SOURCE+= pgp_gpg.c
    CFLAGS+= -DUSE_NETPGP $(NETGPG_INC)
    LDFLAGS+= $(NETGPG_LIB)
    LDLIBS+= -lnetpgp -lcurl
else
    $(error Unknown OpenPGP library: $(OPENPGP))
endif

ALL_SOURCE=$(filter-out $(NO_SOURCE),$(wildcard *.c))
DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

.PHONY: all
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
	$(CC) $(ALL_OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: objects
objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	ar -rc $@ $^

.PHONY: clean
clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~
	rm -Rf $(TARGET).dSYM
	rm -f KeySync_fsm.* Sync_actions.c Sync_event.* Sync_func.* Sync_impl.* sync_codec.*

.PHONY: install
install: $(TARGET)
	mkdir -p "$(PREFIX)/lib/"
	cp $< $(PREFIX)/lib/
	mkdir -p $(PREFIX)/include/pEp
	cp -v pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h \
	      timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h \
	      cryptotech.h sync_api.h blacklist.h pEp_string.h openpgp_compat.h \
	      labeled_int_list.h key_reset.h base64.h sync_codec.h \
		  ../asn.1/*.h $(PREFIX)/include/pEp/

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)
	rm -rf $(PREFIX)/include/pEp

.PHONY: tags
tags:
	ctags *.c *.h

