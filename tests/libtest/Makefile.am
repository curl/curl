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
# $(srcdir) for the generated bundle source to find included test sources

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(srcdir)

# Get BUNDLE, FIRST_C, FIRST_H, UTILS_C, UTILS_H, CURLX_C, TESTS_C variables
include Makefile.inc

EXTRA_DIST = CMakeLists.txt $(FIRST_C) $(FIRST_H) $(UTILS_C) $(UTILS_H) $(TESTS_C) \
  test307.pl test610.pl test613.pl test795.pl test1013.pl test1022.pl mk-lib1521.pl

CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif
if DEBUGBUILD
AM_CPPFLAGS += -DDEBUGBUILD
endif
if CURLDEBUG
AM_CPPFLAGS += -DCURLDEBUG
endif

if USE_CPPFLAG_CURL_STATICLIB
curlx_c_lib =
else
# These are part of the libcurl static lib. Add them here when linking shared.
curlx_c_lib = $(CURLX_C)
endif
$(BUNDLE).c: $(top_srcdir)/scripts/mk-unity.pl Makefile.inc $(FIRST_C) $(UTILS_C) $(curlx_c_lib) $(TESTS_C) lib1521.c
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl --include $(UTILS_C) $(curlx_c_lib) --test $(TESTS_C) lib1521.c > $(BUNDLE).c

noinst_PROGRAMS = $(BUNDLE)
LDADD = $(top_builddir)/lib/libcurl.la @LIBCURL_PC_LIBS_PRIVATE@
CLEANFILES = $(BUNDLE).c lib1521.c

lib1521.c: $(top_srcdir)/tests/libtest/mk-lib1521.pl $(top_srcdir)/include/curl/curl.h
	@PERL@ $(top_srcdir)/tests/libtest/mk-lib1521.pl < $(top_srcdir)/include/curl/curl.h lib1521.c

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc: lib1521.c
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	  -W$(srcdir)/$(BUNDLE).c \
	  $(srcdir)/*.[ch])

if NOT_CURL_CI
all-local: checksrc
endif

clean-local:
	rm -f $(BUNDLE)
