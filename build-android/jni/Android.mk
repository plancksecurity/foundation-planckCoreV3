# Copyright (C) 2015 pEp
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(LIBETPAN_PATH),)
$(error LIBETPAN_PATH must be set)
endif

ifeq ($(GPGME_INCLUDE_PATH),)
$(error GPGME_INCLUDE_PATH must be set)
endif

LOCAL_MODULE    := pEpEngine
LOCAL_CFLAGS    += -std=c99
LOCAL_SRC_FILES := ../../src/bloblist.c \
                   ../../src/cryptotech.c \
                   ../../src/email.c \
                   ../../src/etpan_mime.c \
                   ../../src/identity_list.c \
                   ../../src/keymanagement.c \
                   ../../src/message_api.c \
                   ../../src/message.c \
                   ../../src/mime.c \
                   ../../src/pEpEngine.c \
                   ../../src/pgp_gpg.c \
                   ../../src/platform_unix.c \
                   ../../src/sqlite3.c \
                   ../../src/stringlist.c \
                   ../../src/stringpair.c \
                   ../../src/timestamp.c \
                   ../../src/trans_auto.c \
                   ../../src/transport.c \
                   ../../src/blacklist.c \
                   ../../asn.1/UTF8String.h \
                   ../../asn.1/INTEGER.h \
                   ../../asn.1/NativeEnumerated.h \
                   ../../asn.1/INTEGER.c \
                   ../../asn.1/NativeEnumerated.c \
                   ../../asn.1/NativeInteger.h \
                   ../../asn.1/NativeInteger.c \
                   ../../asn.1/PrintableString.h \
                   ../../asn.1/PrintableString.c \
                   ../../asn.1/UTF8String.c \
                   ../../asn.1/asn_SEQUENCE_OF.h \
                   ../../asn.1/asn_SEQUENCE_OF.c \
                   ../../asn.1/asn_SET_OF.h \
                   ../../asn.1/asn_SET_OF.c \
                   ../../asn.1/constr_SEQUENCE.h \
                   ../../asn.1/constr_SEQUENCE.c \
                   ../../asn.1/constr_SEQUENCE_OF.h \
                   ../../asn.1/constr_SEQUENCE_OF.c \
                   ../../asn.1/constr_SET_OF.h \
                   ../../asn.1/constr_SET_OF.c \
                   ../../asn.1/asn_application.h \
                   ../../asn.1/asn_system.h \ \
                   ../../asn.1/asn_codecs.h \
                   ../../asn.1/asn_internal.h \
                   ../../asn.1/OCTET_STRING.h \
                   ../../asn.1/OCTET_STRING.c \
                   ../../asn.1/BIT_STRING.h \
                   ../../asn.1/BIT_STRING.c \
                   ../../asn.1/asn_codecs_prim.c \
                   ../../asn.1/asn_codecs_prim.h \
                   ../../asn.1/ber_tlv_length.h \
                   ../../asn.1/ber_tlv_length.c \
                   ../../asn.1/ber_tlv_tag.h \
                   ../../asn.1/ber_tlv_tag.c \
                   ../../asn.1/ber_decoder.h \
                   ../../asn.1/ber_decoder.c \
                   ../../asn.1/der_encoder.h \
                   ../../asn.1/der_encoder.c \
                   ../../asn.1/constr_TYPE.h \
                   ../../asn.1/constr_TYPE.c \
                   ../../asn.1/constraints.h \
                   ../../asn.1/constraints.c \
                   ../../asn.1/xer_support.h \
                   ../../asn.1/xer_support.c \ \
                   ../../asn.1/xer_decoder.h \
                   ../../asn.1/xer_decoder.c \
                   ../../asn.1/xer_encoder.h \
                   ../../asn.1/xer_encoder.c \
                   ../../asn.1/per_support.h \
                   ../../asn.1/per_support.c \
                   ../../asn.1/per_decoder.h \
                   ../../asn.1/per_decoder.c \
                   ../../asn.1/per_encoder.h \
                   ../../asn.1/per_encoder.c \
                   ../../asn.1/per_opentype.h \
                   ../../asn.1/per_opentype.c

LOCAL_C_INCLUDES := ../../src \
                    $(GPGME_INCLUDE_PATH) \
                    $(LIBETPAN_PATH)/include

include $(BUILD_STATIC_LIBRARY)
