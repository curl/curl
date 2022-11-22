#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1999 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

# Build libcurl via lib/Makefile.mk first.

PROOT := ../..

ifeq ($(findstring -static,$(CFG)),)
  DYN := 1
endif

### Common

include $(PROOT)/lib/Makefile.mk

### Local

CPPFLAGS += -DCURL_NO_OLDIES
LDFLAGS  += -L$(PROOT)/lib
LIBS     := -lcurl $(LIBS)

ifdef DYN
  curl_DEPENDENCIES += $(PROOT)/lib/libcurl.dll.a
else
  curl_DEPENDENCIES := $(PROOT)/lib/libcurl.a
  ifdef WIN32
    CPPFLAGS += -DCURL_STATICLIB
    LDFLAGS += -static
  endif
endif

ifdef WIN32
  LIBS += -lws2_32
endif

### Sources and targets

# Provides check_PROGRAMS
include Makefile.inc

ifdef WIN32
check_PROGRAMS += synctime
endif

TARGETS := $(patsubst %,%$(BIN_EXT),$(strip $(check_PROGRAMS)))
TOCLEAN := $(TARGETS)

### Rules

%$(BIN_EXT): %.c $(curl_DEPENDENCIES)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(CURL_LDFLAGS_BIN) $< -o $@ $(LIBS)

all: $(TARGETS)
