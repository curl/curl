# Google Android makefile for curl and libcurl
# Place the curl source (including this makefile) into external/curl/ in the
# Android source tree.  Then build them with 'make curl' or just 'make libcurl'
# from the Android root.
#
# Note: you must first create a curl_config.h file by running configure in the
# Android environment. I haven't found an easy way to do this yet. If there is
# no easy way, a static config-android.h may need to be created and checked in
# to the libcurl source tree.
#
# Dan Fandrich
# July 2009

LOCAL_PATH:= $(call my-dir)

common_CFLAGS := -Wpointer-arith -Wwrite-strings -Wunused -Winline -Wnested-externs -Wmissing-declarations -Wmissing-prototypes -Wno-long-long -Wfloat-equal -Wno-multichar -Wsign-compare -Wno-format-nonliteral -Wendif-labels -Wstrict-prototypes -Wdeclaration-after-statement -Wno-system-headers -DHAVE_CONFIG_H

#########################
# Build the libcurl library

include $(CLEAR_VARS)
include $(LOCAL_PATH)/lib/Makefile.inc
CURL_HEADERS := \
	curlbuild.h \
	curl.h \
	curlrules.h \
	curlver.h \
	easy.h \
	mprintf.h \
	multi.h \
	stdcheaders.h \
	typecheck-gcc.h \
	types.h

LOCAL_SRC_FILES := $(addprefix lib/,$(CSOURCES))
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/
LOCAL_CFLAGS += $(common_CFLAGS)

LOCAL_COPY_HEADERS_TO := libcurl/curl
LOCAL_COPY_HEADERS := $(addprefix include/curl/,$(CURL_HEADERS))

LOCAL_MODULE:= libcurl

include $(BUILD_STATIC_LIBRARY)


#########################
# Build the curl binary

include $(CLEAR_VARS)
include $(LOCAL_PATH)/src/Makefile.inc
LOCAL_SRC_FILES := $(addprefix src/,$(CURL_SOURCES))

LOCAL_MODULE := curl
LOCAL_STATIC_LIBRARIES := libcurl
LOCAL_SYSTEM_SHARED_LIBRARIES := libc

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include $(LOCAL_PATH)/lib

# This will also need to include $(CURLX_ONES) in order to correctly build
# a dynamic library
LOCAL_CFLAGS += $(common_CFLAGS)

include $(BUILD_EXECUTABLE)

