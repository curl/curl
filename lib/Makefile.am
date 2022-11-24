#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

CMAKE_DIST = CMakeLists.txt curl_config.h.cmake

EXTRA_DIST = Makefile.mk config-win32.h config-win32ce.h config-plan9.h    \
 config-riscos.h config-mac.h curl_config.h.in config-dos.h                \
 libcurl.plist libcurl.rc config-amigaos.h config-win32ce.h                \
 config-os400.h setup-os400.h $(CMAKE_DIST) setup-win32.h .checksrc

lib_LTLIBRARIES = libcurl.la

if BUILD_UNITTESTS
noinst_LTLIBRARIES = libcurlu.la
else
noinst_LTLIBRARIES =
endif

# This might hold -Werror
CFLAGS += @CURL_CFLAG_EXTRAS@

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "private" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

VERSIONINFO=-version-info 12:0:8
# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# Here's the simplified rule guide on how to change -version-info:
# (current version is C:R:A)
#
# 1. if there are only source changes, use C:R+1:A
# 2. if interfaces were added use C+1:0:A+1
# 3. if interfaces were removed, then use C+1:0:0
#
# For the full guide on libcurl ABI rules, see docs/libcurl/ABI

AM_CPPFLAGS += -DBUILDING_LIBCURL
AM_LDFLAGS =
AM_CFLAGS =

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcurl_la_SOURCES = $(CSOURCES) $(HHEADERS)
libcurlu_la_SOURCES = $(CSOURCES) $(HHEADERS)

libcurl_la_CPPFLAGS_EXTRA =
libcurl_la_LDFLAGS_EXTRA =
libcurl_la_CFLAGS_EXTRA =

if CURL_LT_SHLIB_USE_VERSION_INFO
libcurl_la_LDFLAGS_EXTRA += $(VERSIONINFO)
endif

if CURL_LT_SHLIB_USE_NO_UNDEFINED
libcurl_la_LDFLAGS_EXTRA += -no-undefined
endif

if CURL_LT_SHLIB_USE_MIMPURE_TEXT
libcurl_la_LDFLAGS_EXTRA += -mimpure-text
endif

if CURL_LT_SHLIB_USE_VERSIONED_SYMBOLS
libcurl_la_LDFLAGS_EXTRA += -Wl,--version-script=libcurl.vers
else
# if symbol-hiding is enabled, hide them!
if DOING_CURL_SYMBOL_HIDING
libcurl_la_LDFLAGS_EXTRA += -export-symbols-regex '^curl_.*'
endif
endif

if USE_CPPFLAG_CURL_STATICLIB
libcurl_la_CPPFLAGS_EXTRA += -DCURL_STATICLIB
else
if HAVE_WINDRES
libcurl_la_SOURCES += $(LIB_RCFILES)
$(LIB_RCFILES): $(top_srcdir)/include/curl/curlver.h
endif
endif

if DOING_CURL_SYMBOL_HIDING
libcurl_la_CPPFLAGS_EXTRA += -DCURL_HIDDEN_SYMBOLS
libcurl_la_CFLAGS_EXTRA += $(CFLAG_CURL_SYMBOL_HIDING)
endif

libcurl_la_CPPFLAGS = $(AM_CPPFLAGS) $(libcurl_la_CPPFLAGS_EXTRA)
libcurl_la_LDFLAGS = $(AM_LDFLAGS) $(libcurl_la_LDFLAGS_EXTRA) $(LDFLAGS) $(LIBCURL_LIBS)
libcurl_la_CFLAGS = $(AM_CFLAGS) $(libcurl_la_CFLAGS_EXTRA)

libcurlu_la_CPPFLAGS = $(AM_CPPFLAGS) -DCURL_STATICLIB -DUNITTESTS
libcurlu_la_LDFLAGS = $(AM_LDFLAGS) -static $(LIBCURL_LIBS)
libcurlu_la_CFLAGS = $(AM_CFLAGS)

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir)    \
	-W$(srcdir)/curl_config.h $(srcdir)/*.[ch] $(srcdir)/vauth/*.[ch]   \
	$(srcdir)/vtls/*.[ch] $(srcdir)/vquic/*.[ch] $(srcdir)/vssh/*.[ch])

if CURLDEBUG
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif

# disable the tests that are mostly causing false positives
TIDYFLAGS=-checks=-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-optin.performance.Padding,-clang-analyzer-valist.Uninitialized,-clang-analyzer-core.NonNullParamChecker,-clang-analyzer-core.NullDereference -quiet

TIDY:=clang-tidy

tidy:
	$(TIDY) $(CSOURCES) $(TIDYFLAGS) -- $(AM_CPPFLAGS) $(CPPFLAGS) -DHAVE_CONFIG_H

optiontable:
	perl optiontable.pl < $(top_srcdir)/include/curl/curl.h > easyoptions.c

if HAVE_WINDRES
.rc.lo:
	$(LIBTOOL) --tag=RC --mode=compile $(RC) -I$(top_srcdir)/include $(RCFLAGS) -i $< -o $@
endif
