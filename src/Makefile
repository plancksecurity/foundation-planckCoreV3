# Copyright 2017, pEp Security SA
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../Makefile.conf

CFLAGS+= $(ETPAN_INC) -I../asn.1 -DSYSTEM_DB=\"$(SYSTEM_DB)\" $(EXTRA_MACROS)
LDFLAGS+= $(ETPAN_LIB) -L../asn.1 -shared
LDLIBS+= -lc -lasn1 -letpan 

ifeq ($(BUILD_ON),Darwin)
    ifeq ($(BUILD_FOR),Darwin)
        #CFLAGS+= -I/opt/local/include
        #LDFLAGS+= -L/opt/local/lib
        LDLIBS+= -lsqlite3 -lz -liconv
    else
        $(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else ifeq ($(BUILD_ON),Linux)
    ifeq ($(BUILD_FOR),Linux)
        # FIXME Find out if SQLITE_THREADSAFE is needed for both platform.
        CFLAGS+= -DSQLITE_THREADSAFE=1 -D_GNU_SOURCE
        LDLIBS+= -ldl -luuid
    else
        $(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
    endif
else
    $(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif


ifeq ($(OPENPGP),GPG)
    NO_SOURCE=pgp_netpgp.c
    CFLAGS+= -DUSE_GPG $(GPGME_INC) -DLIBGPGME=\"$(LIBGPGME)\"
    # FIXME Why was -lgpgme commented out?
    LDFLAGS+= $(GPGME_LIB)
else ifeq ($(OPENPGP),NETPGP)
    NO_SOURCE=pgp_gpg.c
    CFLAGS+= -DUSE_NETPGP $(NETGPG_INC)
    LDFLAGS+= $(NETGPG_LIB)
    LDLIBS+= -lnetpgp -lcurl
else
    $(error Unknown OpenPGP library: $(OPENPGP))
endif

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))
DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

.PHONY: all
all: $(TARGET)

# FIXME What is this?
include Makefile.protocols

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPENDS)

$(TARGET): libpEpEngine.a
	$(LD) $(ALL_OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: object
objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	ar -rc $@ $^

.PHONY: clean
clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~

.PHONY: install
install: $(TARGET)
	cp $< $(PREFIX)/lib/
	mkdir -p $(PREFIX)/include/pEp
	cp pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h cryptotech.h sync.h sync_fsm.h sync_app.h blacklist.h openpgp_compat.h $(PREFIX)/include/pEp/

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)
	rm -rf $(PREFIX)/include/pEp

