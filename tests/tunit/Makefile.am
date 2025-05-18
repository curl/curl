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
              -I$(top_srcdir)/tests/unit     \
              -I$(top_srcdir)/tests/tunit

EXTRA_DIST = CMakeLists.txt README.md

CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

LDADD = $(top_builddir)/src/libcurltool.la   \
        $(top_builddir)/lib/libcurl.la      \
        @LIBCURL_PC_LDFLAGS_PRIVATE@ @LIBCURL_PC_LIBS_PRIVATE@

AM_CPPFLAGS += -DCURL_STATICLIB -DUNITTESTS
if DEBUGBUILD
AM_CPPFLAGS += -DDEBUGBUILD
endif
if CURLDEBUG
AM_CPPFLAGS += -DCURLDEBUG
endif

BUNDLE=tunits

if BUILD_UNITTESTS
if USE_TEST_BUNDLES
tool_bundle.c: $(top_srcdir)/tests/mk-bundle.pl Makefile.inc
	@PERL@ $(top_srcdir)/tests/mk-bundle.pl $(srcdir) > tool_bundle.c

noinst_PROGRAMS = $(BUNDLE)
nodist_tunits_SOURCES = tool_bundle.c
CLEANFILES = tool_bundle.c
else
# Makefile.inc provides neat definitions
include Makefile.inc
noinst_PROGRAMS = $(TOOLPROGS)
endif
else
noinst_PROGRAMS =
endif

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	  -W$(srcdir)/tool_bundle.c \
	  $(srcdir)/*.[ch])

if NOT_CURL_CI
all-local: checksrc
endif

clean-local:
	rm -f $(BUNDLE)
