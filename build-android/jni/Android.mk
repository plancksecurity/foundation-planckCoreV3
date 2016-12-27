# Copyleft 2015 pEp foundation
#
# This file is under GNU General Public License 3.0
# see LICENSE.txt

LOCAL_PATH := $(call my-dir)
$(warning $(LOCAL_PATH))

include $(CLEAR_VARS)

ifeq ($(LIBETPAN_PATH),)
$(error LIBETPAN_PATH must be set)
endif

ifeq ($(GPGME_INCLUDE_PATH),)
$(error GPGME_INCLUDE_PATH must be set)
endif

LOCAL_MODULE    := pEpEngine
LOCAL_CFLAGS    += -std=c99

ifneq ($(NDEBUG),)
LOCAL_CFLAGS    += -DNDEBUG=1
endif

# from http://www.sqlite.org/android/finfo?name=jni/sqlite/Android.mk 
#      http://www.sqlite.org/android/artifact/e8ed354b3e58c835

# This is important - it causes SQLite to use memory for temp files. Since 
# Android has no globally writable temp directory, if this is not defined the
# application throws an exception when it tries to create a temp file.
#
LOCAL_CFLAGS    += -DSQLITE_TEMP_STORE=3

LOCAL_C_INCLUDES := ../../src \
                    ../../asn.1 \
                    $(GPGME_INCLUDE_PATH) \
                    $(LIBETPAN_PATH)/include
ENGINE_SRC_FILES := $(shell find ../../src/ ! -name "*netpgp*" -name "*.c")
#ENGINE_SRC_FILES := $(wildcard $(LOCAL_PATH)/../../src/*.c)
$(warning $(ENGINE_SRC_FILES))
ASN1_SRC_FILES := $(wildcard $(LOCAL_PATH)/../../asn.1/*.c)
LOCAL_SRC_FILES := $(ENGINE_SRC_FILES:%=%)  $(ASN1_SRC_FILES:$(LOCAL_PATH)/%=%)


include $(BUILD_STATIC_LIBRARY)
