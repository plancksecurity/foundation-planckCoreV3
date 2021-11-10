# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../Makefile.conf

ifneq ($(BUILD_ON),OS/390)
LDFLAGS+= -shared
endif

NO_SOURCE=

ifndef PEP_MIME
ifeq ($(BUILD_ON),OS/390)
    LDLIBS+= -letpan-no-mt
else
    LDLIBS+= -letpan
endif
else
    LDLIBS+= -lpEpMIME
    NO_SOURCE+= etpan_mime.c
endif
    
CFLAGS+= -I../asn.1 $(EXTRA_MACROS)
CPPFLAGS+= -DSQLITE_THREADSAFE=1

LDFLAGS+= -L../asn.1
ifneq ($(BUILD_ON),OS/390)
LDFLAGS+= -shared
LDLIBS+= -lc
endif
LDLIBS+= -lasn1

ifeq ($(BUILD_ON),OS/390)
    OPENPGP=NETPGP
    LDLIBS+= -lzz
else ifeq ($(BUILD_ON),Darwin)
    ifeq ($(BUILD_FOR),Darwin)
        LDLIBS+= -lz -liconv -mmacosx-version-min=10.10
    else
        $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else ifeq ($(BUILD_ON),Linux)
    ifeq ($(BUILD_FOR),Linux)
        CPPFLAGS+= -D_GNU_SOURCE
        LDLIBS+= -ldl -luuid
    else
        $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else
    $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ifdef SQLITE3_FROM_OS
    NO_SOURCE+= sqlite3.c
    CPPFLAGS+= -DSQLITE3_FROM_OS
    LDLIBS+= -lsqlite3
endif

ifeq ($(OPENPGP),SEQUOIA)
    CPPFLAGS+= -DUSE_SEQUOIA
    CFLAGS+= $(SEQUOIA_CFLAGS) $(SEQUOIA_INC)
    LDFLAGS+= $(SEQUOIA_LDFLAGS)
    LDLIBS+= $(SEQUOIA_LIB)
    NO_SOURCE+=pgp_netpgp.c
else ifeq ($(OPENPGP),NETPGP)
    CPPFLAGS+= -DUSE_NETPGP
    CFLAGS+= $(NETPGP_CFLAGS) $(NETPGP_INC)
    LDFLAGS+= $(NETPGP_LDFLAGS)
    LDLIBS+= $(NETPGP_LIB)
    NO_SOURCE+=pgp_sequoia.c
else
    $(error Unknown OpenPGP library: $(OPENPGP))
endif

ALL_SOURCE=$(filter-out $(NO_SOURCE),$(wildcard *.c))
DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))
ifeq ($(BUILD_ON),OS/390)
    ALL_OBJECTS+=/usr/lib/GSKCMS64.x
    ALL_OBJECTS+=/usr/lib/CSNPCA64.x
endif

all: $(TARGET)

-include Makefile.protocols

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

# If only the goal 'clean' is given, do not generate and include the '%.d' files.
ifneq ($(MAKECMDGOALS),clean)
    -include $(DEPENDS)
endif

$(TARGET): libpEpEngine.a
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) $(ALL_OBJECTS) $(LDLIBS)

.PHONY: objects clean install_headers install uninstall beinstall

objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	$(AR) -rc $@ $^

clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~
	rm -Rf $(TARGET).dSYM
	rm -f KeySync_fsm.* Sync_actions.c Sync_event.* Sync_func.* Sync_impl.* sync_codec.* distribution_codec.* storage_codec.*

HEADERS_TO_INSTALL = \
  pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h \
  timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h group.h \
  cryptotech.h sync_api.h pEp_string.h openpgp_compat.h engine_sql.h \
  labeled_int_list.h key_reset.h base64.h sync_codec.h distribution_codec.h \
  storage_codec.h status_to_string.h keyreset_command.h platform.h \
  platform_unix.h platform_windows.h platform_zos.h \
  transport.h growing_buf.h $(wildcard ../asn.1/*.h)

# CAVEAT:
# install_headers is needed for building *STANDALONE* pEp MIME - it is NOT used for built-in functionality!!!

install_headers: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/include/pEp
	cp $(HEADERS_TO_INSTALL) $(DESTDIR)$(PREFIX)/include/pEp/

# FIXME: Does anyone but Roker use install_headers? Otherwise, remove the dependency.
install: $(TARGET) install_headers
	mkdir -p "$(DESTDIR)$(PREFIX)/lib/"
	cp -v $< $(DESTDIR)$(PREFIX)/lib/
	cp -v libpEpEngine.a $(DESTDIR)$(PREFIX)/lib/

beinstall: install
	cp platform*.h $(DESTDIR)$(PREFIX)/include/pEp/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET)
	rm -f $(addprefix $(DESTDIR)$(PREFIX)/include/pEp/,$(notdir $(HEADERS_TO_INSTALL)))
	rmdir $(DESTDIR)$(PREFIX)/include/pEp 2> /dev/null || true

tags: $(wildcard *.c) $(wildcard *.h)
	ctags --sort=yes *.c *.h
