# Copyleft 2015 pEp foundation
#
# This file is under GNU General Public License 3.0
# see LICENSE.txt
$(warning ==== PEPENGINE android.mk START)
LOCAL_PATH := $(call my-dir)
LIB_PEP_TRANSPORT_PATH:=$(LOCAL_PATH)/../../submodules/libPlanckTransport
$(warning ==== IN PEPENGINE: CURRENT LOCAL BUILT MODULE: $(LOCAL_BUILT_MODULE))
$(warning ==== IN PEPENGINE: UUID BUILT MODULE: $(MY_UUID_BUILD))

include $(CLEAR_VARS)

ifeq ($(GPGBUILD),)
$(error GPGBUILD must be set)
endif

LOCAL_MODULE    := pEpEngine
LOCAL_CFLAGS    += -std=c99 $(PEP_LOG)

# from http://www.sqlite.org/android/finfo?name=jni/sqlite/Android.mk 
#      http://www.sqlite.org/android/artifact/e8ed354b3e58c835

# This is important - it causes SQLite to use memory for temp files. Since 
# Android has no globally writable temp directory, if this is not defined the
# application throws an exception when it tries to create a temp file.
#
LOCAL_CFLAGS    += -DSQLITE_TEMP_STORE=3 -DUSE_SEQUOIA

LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../asn.1 \

LOCAL_C_INCLUDES += $(GPGBUILD)/$(TARGET_ARCH_ABI)/include
LOCAL_C_INCLUDES += $(LIB_PEP_TRANSPORT_PATH)/build-android/include/
#LOCAL_EXPORT_C_INCLUDES += $(LIB_PEP_TRANSPORT_PATH)/build-android/include/
#LOCAL_EXPORT_C_INCLUDES += $(GPGBUILD)/$(TARGET_ARCH_ABI)/include
#LOCAL_EXPORT_C_INCLUDES += $(GPGBUILD)/$(TARGET_ARCH_ABI)/include
LOCAL_C_INCLUDES += $(LIB_PEP_TRANSPORT_PATH)/src
#LOCAL_EXPORT_C_INCLUDES += $(LIB_PEP_TRANSPORT_PATH)/src
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include
#LOCAL_EXPORT_C_INCLUDES += $(LOCAL_PATH)/../include

$(shell sh $(LOCAL_PATH)/../takeOutHeaderFiles.sh $(LOCAL_PATH)../../)
LOCAL_EXPORT_C_INCLUDES += $(LOCAL_PATH)../include

#ENGINE_SRC_FILES := $(shell find $(LOCAL_PATH)/../../src/ ! -name "*sequoia*" ! -name "*netpgp*" -name "*.c")
ENGINE_SRC_FILES := $(shell find $(LOCAL_PATH)/../../src/ ! -name "*gpg*" ! -name "*netpgp*" -name "*.c")
#ENGINE_SRC_FILES := $(wildcard $(LOCAL_PATH)/../../src/*.c)
ASN1_SRC_FILES := $(wildcard $(LOCAL_PATH)/../../asn.1/*.c)
LOCAL_SRC_FILES := $(ENGINE_SRC_FILES:%=%)  $(ASN1_SRC_FILES:$(LOCAL_PATH)/%=%)

LOCAL_STATIC_LIBRARIES := pEpTransport

include $(BUILD_STATIC_LIBRARY)

$(call import-add-path,$(SRC_PATH))
$(warning ==== PEPENGINE android.mk CALLING import-module LIBPEPTRANSPORT)
$(call import-module, libPlanckTransport/build-android/jni/)
