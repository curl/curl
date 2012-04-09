#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_builddir)/include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/include for generated curlbuild.h included from lib/setup.h
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib is for libcurl's lib/setup.h and other "borrowed" files
# $(top_builddir)/ares is for in-tree c-ares's generated ares_build.h file
# $(top_srcdir)/ares is for in-tree c-ares's external include files

if USE_EMBEDDED_ARES
INCLUDES = -I$(top_builddir)/include/curl \
           -I$(top_builddir)/include      \
           -I$(top_srcdir)/include        \
           -I$(top_builddir)/lib          \
           -I$(top_srcdir)/lib            \
           -I$(top_srcdir)/tests/libtest  \
           -I$(top_builddir)/ares         \
           -I$(top_srcdir)/ares
else
INCLUDES = -I$(top_builddir)/include/curl \
           -I$(top_builddir)/include      \
           -I$(top_srcdir)/include        \
           -I$(top_builddir)/lib          \
           -I$(top_srcdir)/lib            \
           -I$(top_srcdir)/tests/libtest
endif

EXTRA_DIST = Makefile.inc

LDADD = $(top_builddir)/lib/libcurlu.la @LDFLAGS@ @LIBCURL_LIBS@ @LIBS@
DEPENDENCIES = $(top_builddir)/lib/libcurlu.la
AM_CPPFLAGS = -DUNITTESTS

# Mostly for Windows build targets, when using static libcurl
if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif

# Makefile.inc provides neat definitions
include Makefile.inc

if BUILD_UNITTESTS
noinst_PROGRAMS = $(UNITPROGS)
else
noinst_PROGRAMS =
endif
