include ../Makefile.conf

LD?=$(CC)

ETPAN_IN?=$(HOME)

ifeq ($(BUILD_ON),Darwin)
ifeq ($(BUILD_FOR),Darwin)

TARGET?=libpEpEngine.dylib
MACOSX_VERSION_MIN=10.6
LIBGPGME?=libgpgme.dylib
CC?=clang -std=c99 -pthread
CFLAGS?= -I$(ETPAN_IN)/include -I/opt/local/include -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -I../asn.1 $(EXTRAMACROS)
LDFLAGS?= -lc -shared -arch x86_64 \
	-L$(ETPAN_IN)/lib -L/usr/lib -L/opt/local/lib -letpan -lsqlite3 -L../asn.1 -lasn1 -lz -liconv

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else ifeq ($(BUILD_ON),Linux)
ifeq ($(BUILD_FOR),Linux)

TARGET=libpEpEngine.so
LIBGPGME?=libgpgme.so.11
CC=gcc -std=c99
CFLAGS?= -I$(ETPAN_IN)/include -fPIC -pedantic -DSYSTEM_DB=\"$(SYSTEM_DB)\" \
	-DSQLITE_THREADSAFE=1 -D_GNU_SOURCE -I../asn.1 $(EXTRAMACROS)
LDFLAGS?= -L$(ETPAN_IN)/lib -shared -lc -ldl -letpan -lpthread -L../asn.1 -lasn1 -luuid

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

DEBUG?=NO
ifeq ("$(DEBUG)","NO")
    CFLAGS+= -DNDEBUG
endif

OPENPGP?=GPG
ifeq ("$(OPENPGP)","GPG")
    NO_SOURCE=pgp_netpgp.c
    GPGME_IN?=$(HOME)
    CFLAGS+= -DUSE_GPG -I$(GPGME_IN)/include -DLIBGPGME=\"$(LIBGPGME)\"
    #LDFLAGS+= -L$(GPGME_IN)/lib -lgpgme
else ifeq ("$(OPENPGP)","NETPGP")
    NO_SOURCE=pgp_gpg.c
    NETPGP_IN?=$(HOME)
    CFLAGS+= -DUSE_NETPGP -I$(NETPGP_IN)/include
    LDFLAGS+= -L$(NETPGP_IN)/lib -lnetpgp -lcurl
else
	$(error Unknown OpenPGP library : $(OPENPGP))
endif

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))

DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

all: $(TARGET)

include Makefile.protocols

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPENDS)

#platform_windows.o: platform_windows.cpp
#	$(CXX) $(CXX_FLAGS) -o $@ -c $<

$(TARGET): libpEpEngine.a
	$(LD) $(ALL_OBJECTS) $(LDFLAGS) -o $@

objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	ar -r $@ $(ALL_OBJECTS)

.PHONY: clean

clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~

install: $(TARGET)
	cp $< $(PREFIX)/lib/
	mkdir -p $(PREFIX)/include/pEp
	cp pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h cryptotech.h sync.h sync_fsm.h sync_app.h blacklist.h openpgp_compat.h $(PREFIX)/include/pEp/

uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)

