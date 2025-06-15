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

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(srcdir)

# Get BUNDLE, BUNDLE_SRC, FIRSTFILES, TESTFILES variables
include Makefile.inc

EXTRA_DIST = CMakeLists.txt $(FIRSTFILES) $(TESTFILES)

CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

LIBDIR = $(top_builddir)/lib

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif
if DOING_NATIVE_WINDOWS
AM_CPPFLAGS += -DWIN32_LEAN_AND_MEAN
endif

AM_CPPFLAGS += -DCURL_NO_OLDIES

$(BUNDLE_SRC): $(top_srcdir)/scripts/mk-unity.pl Makefile.inc $(FIRSTFILES) $(TESTFILES)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl --test $(TESTFILES) > $(BUNDLE_SRC)

noinst_PROGRAMS = $(BUNDLE)
nodist_clients_SOURCES = $(BUNDLE_SRC)
clients_SOURCES =
clients_LDADD = $(LIBDIR)/libcurl.la @LIBCURL_PC_LIBS_PRIVATE@
clients_CFLAGS = $(AM_CFLAGS)
CLEANFILES = $(BUNDLE_SRC)

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	  -W$(srcdir)/$(BUNDLE_SRC) \
	  $(srcdir)/*.[ch])

if NOT_CURL_CI
all-local: checksrc
endif

clean-local:
	rm -f $(BUNDLE)
