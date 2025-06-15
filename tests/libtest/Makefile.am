#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/lib/curlx      \
              -I$(top_srcdir)/src            \
              -I$(top_srcdir)/tests/libtest  \
              -I$(top_srcdir)/tests/unit

# Get BUNDLE, BUNDLE_SRC, FIRSTFILES, UTILS, MEMPTR, CURLX_SRCS, TESTFILES variables
include Makefile.inc

EXTRA_DIST = CMakeLists.txt .checksrc $(FIRSTFILES) $(UTILS) $(MEMPTR) $(TESTFILES) \
  test307.pl test610.pl test613.pl test1013.pl test1022.pl mk-lib1521.pl

CFLAG_CURL_SYMBOL_HIDING = @CFLAG_CURL_SYMBOL_HIDING@

CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

# Dependencies (may need to be overridden)
LDADD = $(top_builddir)/lib/libcurl.la @LIBCURL_PC_LIBS_PRIVATE@

noinst_LTLIBRARIES =

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif
if DEBUGBUILD
AM_CPPFLAGS += -DDEBUGBUILD
endif
if CURLDEBUG
AM_CPPFLAGS += -DCURLDEBUG
endif

AM_CPPFLAGS += -DCURL_NO_OLDIES -DCURL_DISABLE_DEPRECATION

AM_LDFLAGS =
AM_CFLAGS =

# Build a stub gssapi implementation for testing
if BUILD_STUB_GSS
noinst_LTLIBRARIES += libstubgss.la

libstubgss_la_CPPFLAGS = $(AM_CPPFLAGS)
libstubgss_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -rpath /nowhere
if CURL_LT_SHLIB_USE_NO_UNDEFINED
libstubgss_la_LDFLAGS += -no-undefined
endif
libstubgss_la_CFLAGS = $(AM_CFLAGS) -g
libstubgss_la_SOURCES = stub_gssapi.c stub_gssapi.h
libstubgss_la_LIBADD =
libstubgss_la_DEPENDENCIES =
endif

bundle_extra =
if USE_CPPFLAG_CURL_STATICLIB
else
# These are part of the libcurl static lib. Add them here when linking shared.
bundle_extra += $(CURLX_SRCS)
endif
$(BUNDLE_SRC): $(top_srcdir)/scripts/mk-unity.pl Makefile.inc $(FIRSTFILES) $(UTILS) $(MEMPTR) $(bundle_extra) $(TESTFILES) lib1521.c
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl --include $(UTILS) $(MEMPTR) $(bundle_extra) --test $(TESTFILES) lib1521.c > $(BUNDLE_SRC)

noinst_PROGRAMS = $(BUNDLE)
nodist_libtests_SOURCES = $(BUNDLE_SRC)
libtests_SOURCES =
CLEANFILES = $(BUNDLE_SRC) lib1521.c

lib1521.c: $(top_srcdir)/tests/libtest/mk-lib1521.pl $(top_srcdir)/include/curl/curl.h
	@PERL@ $(top_srcdir)/tests/libtest/mk-lib1521.pl < $(top_srcdir)/include/curl/curl.h lib1521.c

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc: lib1521.c
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	  -W$(srcdir)/$(BUNDLE_SRC) \
	  $(srcdir)/*.[ch])

if NOT_CURL_CI
all-local: checksrc
endif

clean-local:
	rm -f $(BUNDLE)
