# Google Android makefile for curl and libcurl
#
# Place the curl source (including this makefile) into external/curl/ in the
# Android source tree.  Then build them with 'make curl' or just 'make libcurl'
# from the Android root. Tested with Android 1.5
#
# Note: you must first create a curl_config.h file by running configure in the
# Android environment. The only way I've found to do this is tricky. Perform a
# normal Android build with libcurl in the source tree, providing the target
# "showcommands" to make. The build will eventually fail (because curl_config.h
# doesn't exist yet), but the compiler commands used to build curl will be
# shown. Now, from the external/curl/ directory, run curl's normal configure
# command with flags that match what Android itself uses. This will mean
# putting the compiler directory into the PATH, putting the -I, -isystem and
# -D options into CPPFLAGS, putting the -m, -f, -O and -nostdlib options into
# CFLAGS, and putting the -Wl, -L and -l options into LIBS, along with the path
# to the files libgcc.a, crtbegin_dynamic.o, and ccrtend_android.o. Remember
# that the paths must be absolute since you will not be running configure from
# the same directory as the Android make.  The normal cross-compiler options
# must also be set.
#
# The end result will be a configure command that looks something like this
# (the environment variable A is set to the Android root path):
#
#  A=`realpath ../..` && \
#  PATH="$A/prebuilt/linux-x86/toolchain/arm-eabi-X/bin:$PATH" \
#  ./configure --host=arm-linux CC=arm-eabi-gcc \
#  CPPFLAGS="-I $A/system/core/include ..." \
#  CFLAGS="-fno-exceptions -Wno-multichar ..." \
#  LIB="$A/prebuilt/linux-x86/toolchain/arm-eabi-X/lib/gcc/arm-eabi/X\
#  /interwork/libgcc.a ..." \
#
# Dan Fandrich
# September 2009

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

