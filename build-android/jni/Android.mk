# Copyleft 2015 pEp foundation
#
# This file is under GNU General Public License 3.0
# see LICENSE.txt
LOCAL_PATH := $(call my-dir)

LIBETPAN_PATH:=  $(LOCAL_PATH)/../../../pEpJNIAdapter/android/external/libetpan/build-android

include $(CLEAR_VARS)

ifeq ($(LIBETPAN_PATH),)
$(error LIBETPAN_PATH must be set)
endif

LOCAL_MODULE    := pEpEngine
LOCAL_CFLAGS    += -std=c99

# from http://www.sqlite.org/android/finfo?name=jni/sqlite/Android.mk 
#      http://www.sqlite.org/android/artifact/e8ed354b3e58c835

# This is important - it causes SQLite to use memory for temp files. Since 
# Android has no globally writable temp directory, if this is not defined the
# application throws an exception when it tries to create a temp file.
#
LOCAL_CFLAGS    += -DSQLITE_TEMP_STORE=3 -DUSE_SEQUOIA

LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../asn.1 \
                    $(GPGME_INCLUDE_PATH) \
                    $(LIBETPAN_PATH)/include
LOCAL_C_INCLUDES += $(GPGBUILD)/$(TARGET_ARCH_ABI)/app_opt/include

$(shell sh $(LOCAL_PATH)/../takeOutHeaderFiles.sh $(LOCAL_PATH)../../)
LOCAL_EXPORT_C_INCLUDES += $(LOCAL_PATH)../include

#ENGINE_SRC_FILES := $(shell find $(LOCAL_PATH)/../../src/ ! -name "*sequoia*" ! -name "*netpgp*" -name "*.c")
ENGINE_SRC_FILES := $(shell find $(LOCAL_PATH)/../../src/ ! -name "*gpg*" ! -name "*netpgp*" -name "*.c")
#ENGINE_SRC_FILES := $(wildcard $(LOCAL_PATH)/../../src/*.c)
ASN1_SRC_FILES := $(wildcard $(LOCAL_PATH)/../../asn.1/*.c)
LOCAL_SRC_FILES := $(ENGINE_SRC_FILES:%=%)  $(ASN1_SRC_FILES:$(LOCAL_PATH)/%=%)


include $(BUILD_STATIC_LIBRARY)
