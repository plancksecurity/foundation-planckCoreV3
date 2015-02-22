include ../Makefile.conf

ifeq ($(BUILD_ON),Darwin)
ifeq ($(BUILD_FOR),Darwin)

TARGET=libpEpEngine.dylib
MACOSX_VERSION_MIN=10.6
GPGME_IN=$(HOME)
LIBGPGME=libgpgme-pthread.dylib
CC?=clang -std=c99 -pthread
LD?=clang
CFLAGS?=-I$(GPGME_IN)/include -I/opt/local/include $(OPTIMIZE) -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -DLIBGPGME=\"$(LIBGPGME)\"
LDFLAGS?=-lc -shared -arch x86_64 \
	-L/opt/local/lib -letpan -lgpgme-pthread -lsqlite3

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else ifeq ($(BUILD_ON),Linux)
ifeq ($(BUILD_FOR),Linux)

TARGET=libpEpEngine.so
GPGME_IN=$(HOME)
LIBGPGME=libgpgme.so.11
CC?=gcc -std=c99
CFLAGS?=-I$(GPGME_IN)/include $(OPTIMIZE) -fPIC -pedantic \
	-DSYSTEM_DB=\"$(SYSTEM_DB)\" -DLIBGPGME=\"$(LIBGPGME)\" -DSQLITE_THREADSAFE=1
LDFLAGS?=-L$(GPGME_IN) -shared -lc -ldl -letpan -lgpgme-pthread -lsqlite3

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

else
$(error don't know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ALL_SOURCE=$(wildcard *.c)
DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))

all: $(TARGET)

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

uninstall:
	rm -f $(PREFIX)/lib/$(TARGET)

