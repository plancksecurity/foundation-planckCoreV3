# Copyright (C) 2015 pEp
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(OPENSSL_PATH),)
$(error OPENSSL_PATH must be set)
endif

ifeq ($(CYRUS_SASL_PATH),)
$(error CYRUS_SASL_PATH must be set)
endif

ifeq ($(LIBETPAN_PATH),)
$(error LIBETPAN_PATH must be set)
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
                   ../../src/transport.c

LOCAL_C_INCLUDES := ../../src \
                    ../../../gnupg-for-android/external/data/data/info.guardianproject.gpg/app_opt/include \
                    $(OPENSSL_PATH)/include \
                    $(CYRUS_SASL_PATH)/include \
                    $(LIBETPAN_PATH)/include

include $(BUILD_STATIC_LIBRARY)
