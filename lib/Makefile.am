#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

CMAKE_DIST = CMakeLists.txt curl_config.h.cmake

EXTRA_DIST = Makefile.b32 Makefile.m32 Makefile.vc6 config-win32.h	\
 config-win32ce.h config-riscos.h config-mac.h curl_config.h.in		\
 makefile.dj config-dos.h libcurl.plist libcurl.rc config-amigaos.h	\
 makefile.amiga Makefile.netware nwlib.c nwos.c config-win32ce.h	\
 config-os400.h setup-os400.h config-symbian.h Makefile.Watcom		\
 config-tpf.h mk-ca-bundle.pl mk-ca-bundle.vbs $(CMAKE_DIST)	\
 firefox-db2pem.sh config-vxworks.h Makefile.vxworks checksrc.pl	\
 objnames-test08.sh objnames-test10.sh objnames.inc checksrc.whitelist

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
# $(top_builddir)/include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/include for generated curlbuild.h inc. from lib/curl_setup.h
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "private" files
# $(top_builddir)/ares is for in-tree c-ares's generated ares_build.h file
# $(top_srcdir)/ares is for in-tree c-ares's external include files

AM_CPPFLAGS = -I$(top_builddir)/include/curl \
              -I$(top_builddir)/include      \
              -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib

if USE_EMBEDDED_ARES
AM_CPPFLAGS += -I$(top_builddir)/ares        \
               -I$(top_srcdir)/ares
endif

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

if SONAME_BUMP
#
# Bumping of SONAME conditionally may seem like a weird thing to do, and yeah
# it is. The problem is that we try to avoid the bump as hard as possible, but
# yet it is still necessary for a few rare situations. The configure script will
# attempt to figure out these situations, and it can be forced to consider this
# to be such a case! See README.curl_off_t for further details.
#
# This conditional soname bump SHOULD be removed at next "proper" bump.
#
VERSIONINFO=-version-info 8:0:3
else
VERSIONINFO=-version-info 7:0:3
endif

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
endif

if USE_CPPFLAG_CURL_STATICLIB
libcurl_la_CPPFLAGS_EXTRA += -DCURL_STATICLIB
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

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcurl_la_SOURCES = $(CSOURCES) $(HHEADERS)
libcurlu_la_SOURCES = $(CSOURCES) $(HHEADERS)

checksrc:
	@@PERL@ $(top_srcdir)/lib/checksrc.pl -D$(top_srcdir)/lib $(CSOURCES) $(HHEADERS)

if CURLDEBUG
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif
