include ../Makefile.conf

ifeq ($(BUILD_ON),Darwin)
ifeq ($(BUILD_FOR),Darwin)

TARGET=libpEpEngine.dylib
MACOSX_VERSION_MIN=10.6
GPGME_IN=$(HOME)
LIBGPGME=libgpgme-pthread.dylib
CC=gcc -std=c99
CFLAGS=-I$(GPGME_IN)/include -I/opt/local/include $(OPTIMIZE) -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -DLIBGPGME=\"$(LIBGPGME)\"  -DSQLITE_THREADSAFE=1
LDFLAGS=-lc -macosx_version_min $(MACOSX_VERSION_MIN) -dylib -arch x86_64

else ifeq ($(BUILD_FOR),Windoze)

TARGET=pEpEngine.dll
GPGME_IN=$(HOME)
LIBGPGME=libgpgme-11.dll
CC=i686-w64-mingw32-gcc -std=c99
CXX=i686-w64-mingw32-g++
LD=i686-w64-mingw32-gcc
CFLAGS=-I$(HOME)/i686-w64-mingw32/include -I$(GPGME_IN)/include $(OPTIMIZE) -pedantic \
	-DLIBGPGME=\"$(LIBGPGME)\" -DWIN32 -DSQLITE_THREADSAFE=1
LDFLAGS=-shared -L$(HOME)/i686-w64-mingw32/lib -llibstdc++ \
	-Wl,--output-def,pEpEngine.def,--out-implib,libpEpEngine.a

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else ifeq ($(BUILD_ON),Linux)
ifeq ($(BUILD_FOR),Linux)

TARGET=libpEpEngine.so
GPGME_IN=$(HOME)
LIBGPGME=libgpgme.so.11
CC=gcc -std=c99
CFLAGS=-I$(GPGME_IN)/include $(OPTIMIZE) -fPIC -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -DLIBGPGME=\"$(LIBGPGME)\" -DSQLITE_THREADSAFE=1
LDFLAGS=-L$(GPGME_IN) -shared -lc -ldl

else ifeq ($(BUILD_FOR),Windoze)

TARGET=pEpEngine.dll
GPGME_IN=$(HOME)
LIBGPGME=libgpgme-11.dll
CC=i686-w64-mingw32-gcc -std=c99
CXX=i686-w64-mingw32-g++
LD=i686-w64-mingw32-gcc
CFLAGS=-I/usr/i686-w64-mingw32/include -I$(GPGME_IN)/include $(OPTIMIZE) -pedantic \
	-DLIBGPGME=\"$(LIBGPGME)\" -DWIN32 -DSQLITE_THREADSAFE=1
LDFLAGS=-shared -L/usr/i686-w64-mingw32/lib -llibstdc++ \
	-Wl,--output-def,pEpEngine.def,--out-implib,libpEpEngine.a

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else ifeq ($(BUILD_ON),MINGW32_NT-6.1)

TARGET=pEpEngine.dll
GPGME_IN=/c/Program\ Files/GNU/GnuPG
LIBGPGME=libgpgme-11.dll
CC=gcc -std=gnu99
CFLAGS=-I$(GPGME_IN)/include $(OPTIMIZE) -pedantic -DWIN32 -DSQLITE_THREADSAFE=1
LD=gcc
LDFLAGS=-shared -llibstdc++ -Wl,--output-def,pEpEngine.def,--out-implib,libpEpEngine.a

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ifeq ($(BUILD_FOR),Windoze)
ALL_SOURCE=$(filter-out platform_unix.c,$(wildcard *.c))
else ifeq ($(BUILD_FOR),MINGW32_NT-6.1)
ALL_SOURCE=$(filter-out platform_unix.c,$(wildcard *.c))
else
ALL_SOURCE=$(wildcard *.c)
endif

DEPENDS=$(subst .c,.d,$(ALL_SOURCE))

ifeq ($(BUILD_FOR),Windoze)
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE)) platform_windows.o
else ifeq ($(BUILD_FOR),MINGW32_NT-6.1)
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE)) platform_windows.o
else
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))
endif

all: $(TARGET)

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPENDS)

platform_windows.o: platform_windows.cpp
	$(CXX) $(CXX_FLAGS) -o $@ -c $<

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

uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)

