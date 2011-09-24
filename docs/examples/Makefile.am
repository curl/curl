#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

EXTRA_DIST = README Makefile.example Makefile.inc Makefile.m32 \
	Makefile.netware makefile.dj printf_macro.h $(COMPLICATED_EXAMPLES)

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_builddir)/include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/include for generated curlbuild.h included from lib/setup.h
# $(top_srcdir)/include is for libcurl's external include files

INCLUDES = -I$(top_builddir)/include/curl \
           -I$(top_builddir)/include      \
           -I$(top_srcdir)/include

LIBDIR = $(top_builddir)/lib

if STATICLIB
# we need this define when building with a static lib on Windows
STATICCPPFLAGS = -DCURL_STATICLIB
endif

CPPFLAGS = -DCURL_NO_OLDIES $(STATICCPPFLAGS)

# Dependencies
LDADD = $(LIBDIR)/libcurl.la

# Makefile.inc provides the check_PROGRAMS and COMPLICATED_EXAMPLES defines
include Makefile.inc

all: $(check_PROGRAMS)
