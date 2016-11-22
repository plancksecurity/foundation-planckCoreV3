include ../Makefile.conf

OPENPGP?=GPG

ifeq ($(BUILD_ON),Darwin)
ifeq ($(BUILD_FOR),Darwin)

TARGET?=libpEpEngine.dylib
MACOSX_VERSION_MIN=10.6
GPGME_IN=$(HOME)
LIBGPGME?=libgpgme-pthread.dylib
CC?=clang -std=c99 -pthread
LD?=clang
CFLAGS?=-I$(GPGME_IN)/include -I$(HOME)/include -I/opt/local/include $(OPTIMIZE) -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -DLIBGPGME=\"$(LIBGPGME)\" -I../asn.1 $(EXTRAMACROS)
LDFLAGS?=-lc -shared -arch x86_64 \
	-L$(HOME)/lib -L/usr/lib -L/opt/local/lib -letpan -lsqlite3 -L../asn.1 -lasn1 -lz -liconv

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else ifeq ($(BUILD_ON),Linux)
ifeq ($(BUILD_FOR),Linux)

TARGET=libpEpEngine.so
GPGME_IN=$(HOME)
LIBGPGME=libgpgme.so.11
CC=gcc -std=c99
CFLAGS?=-I$(GPGME_IN)/include $(OPTIMIZE) -fPIC -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -DLIBGPGME=\"$(LIBGPGME)\" \
	-DSQLITE_THREADSAFE=1 -D_GNU_SOURCE -I../asn.1 $(EXTRAMACROS)
LDFLAGS?=-L$(GPGME_IN)/lib -shared -lc -ldl -letpan -lpthread -L../asn.1 -lasn1

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ifeq ("$(OPENPGP)","GPG")
	NO_SOURCE=pgp_netpgp.c
	CFLAGS+= -DUSE_GPG
	LDFLAGS+= -lgpgme-pthread 
else ifeq ("$(OPENPGP)","NETPGP")
	NO_SOURCE=pgp_gpg.c
	CFLAGS+= -DUSE_NETPGP
	LDFLAGS+= -lnetpgp -lcurl
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
	cp pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h cryptotech.h sync.h sync_fsm.h blacklist.h openpgp_compat.h $(PREFIX)/include/pEp/

uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)

