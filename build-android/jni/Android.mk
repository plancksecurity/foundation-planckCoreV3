# Copyright (C) 2015 pEp
#
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
