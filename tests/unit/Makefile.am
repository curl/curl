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
              -I$(top_srcdir)/tests/libtest  \
              -I$(srcdir)

# Get BUNDLE, FIRST_C, TESTS_C variables
include Makefile.inc

EXTRA_DIST = CMakeLists.txt README.md $(TESTS_C)

CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

AM_CPPFLAGS += -DCURL_STATICLIB -DUNITTESTS
if DEBUGBUILD
AM_CPPFLAGS += -DDEBUGBUILD
endif
if CURLDEBUG
AM_CPPFLAGS += -DCURLDEBUG
endif
# unit tests are small pretend-libcurl-programs, pass BUILDING_LIBCURL to reflect that
AM_CPPFLAGS += -DBUILDING_LIBCURL

if BUILD_UNITTESTS
$(BUNDLE).c: $(top_srcdir)/scripts/mk-unity.pl Makefile.inc $(FIRST_C) $(TESTS_C) $(top_builddir)/lib/unitprotos.h
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl --test $(TESTS_C) > $(BUNDLE).c

$(top_builddir)/lib/unitprotos.h:
	(cd $(top_builddir)/lib && $(MAKE) unitprotos.h)

noinst_PROGRAMS = $(BUNDLE)
LDADD = $(top_builddir)/lib/libcurlu.la
CLEANFILES = $(BUNDLE).c
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
	  -W$(srcdir)/$(BUNDLE).c \
	  $(srcdir)/*.[ch])

if NOT_CURL_CI
all-local: checksrc
endif

clean-local:
	rm -f $(BUNDLE)
