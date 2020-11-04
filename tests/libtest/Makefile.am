#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files
# $(top_builddir)/ares is for in-tree c-ares's generated ares_build.h file
# $(top_srcdir)/ares is for in-tree c-ares's external include files

if USE_EMBEDDED_ARES
AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(top_builddir)/ares         \
              -I$(top_srcdir)/ares
else
AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib
endif

EXTRA_DIST = test307.pl test610.pl test613.pl test1013.pl \
  test1022.pl Makefile.inc notexists.pl CMakeLists.txt mk-lib1521.pl

CFLAG_CURL_SYMBOL_HIDING = @CFLAG_CURL_SYMBOL_HIDING@

CFLAGS += @CURL_CFLAG_EXTRAS@

CLEANFILES = lib1521.c

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

if USE_EXPLICIT_LIB_DEPS
SUPPORTFILES_LIBS = $(top_builddir)/lib/libcurl.la @LIBCURL_LIBS@
TESTUTIL_LIBS = $(top_builddir)/lib/libcurl.la @LIBCURL_LIBS@
else
SUPPORTFILES_LIBS = $(top_builddir)/lib/libcurl.la @CURL_NETWORK_LIBS@ @NSS_LIBS@
TESTUTIL_LIBS = $(top_builddir)/lib/libcurl.la @CURL_NETWORK_AND_TIME_LIBS@ @NSS_LIBS@
endif

# Dependencies (may need to be overridden)
LDADD = $(SUPPORTFILES_LIBS)

# Makefile.inc provides the source defines (TESTUTIL, SUPPORTFILES,
# noinst_PROGRAMS, lib*_SOURCES, and lib*_CFLAGS)
include Makefile.inc

# Preloading of libhostname allows host name overriding,
# this is used to make some tests machine independent.

if BUILD_LIBHOSTNAME
noinst_LTLIBRARIES = libhostname.la
else
noinst_LTLIBRARIES =
endif

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif

AM_LDFLAGS =
AM_CFLAGS =

libhostname_la_CPPFLAGS_EXTRA =
libhostname_la_LDFLAGS_EXTRA = -module -avoid-version -rpath /nowhere
libhostname_la_CFLAGS_EXTRA =

libstubgss_la_LDFLAGS_EXTRA =

if CURL_LT_SHLIB_USE_NO_UNDEFINED
libhostname_la_LDFLAGS_EXTRA += -no-undefined
libstubgss_la_LDFLAGS_EXTRA += -no-undefined
endif

if CURL_LT_SHLIB_USE_MIMPURE_TEXT
libhostname_la_LDFLAGS_EXTRA += -mimpure-text
endif

if DOING_CURL_SYMBOL_HIDING
libhostname_la_CPPFLAGS_EXTRA += -DCURL_HIDDEN_SYMBOLS
libhostname_la_CFLAGS_EXTRA += $(CFLAG_CURL_SYMBOL_HIDING)
endif

libhostname_la_CPPFLAGS = $(AM_CPPFLAGS) $(libhostname_la_CPPFLAGS_EXTRA)
libhostname_la_LDFLAGS = $(AM_LDFLAGS) $(libhostname_la_LDFLAGS_EXTRA)
libhostname_la_CFLAGS = $(AM_CFLAGS) $(libhostname_la_CFLAGS_EXTRA)

libhostname_la_SOURCES = sethostname.c sethostname.h

libhostname_la_LIBADD =
libhostname_la_DEPENDENCIES =

# Build a stub gssapi implementation for testing
if BUILD_STUB_GSS
noinst_LTLIBRARIES += libstubgss.la

libstubgss_la_CPPFLAGS = $(AM_CPPFLAGS)
libstubgss_la_LDFLAGS = $(AM_LDFLAGS) $(libstubgss_la_LDFLAGS_EXTRA) -avoid-version -rpath /nowhere
libstubgss_la_CFLAGS = $(AM_CFLAGS) -g

libstubgss_la_SOURCES = stub_gssapi.c stub_gssapi.h

libstubgss_la_LIBADD =
libstubgss_la_DEPENDENCIES =
endif


lib1521.c: $(top_srcdir)/tests/libtest/mk-lib1521.pl $(top_srcdir)/include/curl/curl.h
	@PERL@ $(top_srcdir)/tests/libtest/mk-lib1521.pl < $(top_srcdir)/include/curl/curl.h > lib1521.c

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)@PERL@ $(top_srcdir)/lib/checksrc.pl -D$(srcdir) $(srcdir)/*.[ch]

if CURLDEBUG
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif
