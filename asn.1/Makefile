# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

ALL_SOURCE=$(subst $(NO_SOURCE),,$(wildcard *.c))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))
CPPFLAGS+=$(CPPFLAGS_GENERATED)
ASN1C_INC+= -I.
ASN1C_OPTIONS = -fincludes-quoted -fcompound-names -pdu=auto

ifeq ($(BUILD_FOR),Linux)
  # Some code generated by asn1.c contains unconditional definitions of
  # the macro _REENTRANT, which is obsolete but automatically defined for
  # compatibility by recent GNU systems (problem observed after updating
  # debian sid packages in early 2022).
  # Since the macro has not had any useful effect for a long time, an easy
  # workaround is preventing multiple definitions by undefining the macro
  # on the command line before CPP sees the definition in the generated
  # code.
  CPPFLAGS+=-U_REENTRANT
endif

DISTRIBUTION = distribution keyreset managedgroup exploration
SYNC  = sync keysync trustsync groupsync
STORAGE = storage messagestorage

DISTRIBUTION_FILES = $(addsuffix .asn1, $(DISTRIBUTION))
SYNC_FILES         = $(addsuffix .asn1, $(SYNC))
STORAGE_FILES      = $(addsuffix .asn1, $(STORAGE))

.PHONY: all clean install uninstall

all: Sync.c Distribution.c Storage.c ASN1Message.c
	$(MAKE) libasn1.a

libasn1.a: $(ALL_OBJECTS)
	$(AR) -rc $@ $(ALL_OBJECTS)

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OPTIMIZE) $(ASN1C_INC) -c $< -o $@

Sync.c: $(SYNC_FILES) $(DISTRIBUTION_FILES) pEp.asn1  # positrontofdik: is it correct that $(DISTRIBUTION_FILES) is among the dependencies? I would guess not
	$(ASN1C) -gen-PER $(ASN1C_OPTIONS) $+
	rm -f converter-sample.c
	touch Sync.c

Distribution.c: $(DISTRIBUTION_FILES) pEp.asn1
	$(ASN1C) -gen-PER $(ASN1C_OPTIONS) $+
	rm -f converter-sample.c
	touch Distribution.c

Storage.c: $(STORAGE_FILES) pEp.asn1
	$(ASN1C) -gen-PER $(ASN1C_OPTIONS) $+
	rm -f converter-sample.c
	touch Storage.c

ASN1Message.c: message.asn1 pEp.asn1
	$(ASN1C) -gen-PER $(ASN1C_OPTIONS) $+
	rm -f converter-sample.c
	touch ASN1Message.c

clean:
	rm -f *.a *.o *.c *.h *.sample \
		$(SYNC_FILES) $(DISTRIBUTION_FILES) $(STORAGE_FILES)

install:

uninstall:

tags: $(wildcard *.c) $(wildcard *.h)
	ctags --sort=yes *.c *.h

# ensure generated files are here - useful after "make clean"
$(SYNC_FILES) $(DISTRIBUTION_FILES) $(STORAGE_FILES):
	rm -f ../codegen/.copy
	$(MAKE) -C ../codegen .copy
