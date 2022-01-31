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
###########################################################################

AUTOMAKE_OPTIONS = foreign nostdinc

EXTRA_DIST = README.md Makefile.example Makefile.inc Makefile.m32 \
  makefile.dj $(COMPLICATED_EXAMPLES) .checksrc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files

AM_CPPFLAGS = -I$(top_srcdir)/include

LIBDIR = $(top_builddir)/lib

# Avoid libcurl obsolete stuff
AM_CPPFLAGS += -DCURL_NO_OLDIES

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

# Dependencies
if USE_EXPLICIT_LIB_DEPS
LDADD = $(LIBDIR)/libcurl.la @LIBCURL_LIBS@
else
LDADD = $(LIBDIR)/libcurl.la
endif

# This might hold -Werror
CFLAGS += @CURL_CFLAG_EXTRAS@

# Makefile.inc provides the check_PROGRAMS and COMPLICATED_EXAMPLES defines
include Makefile.inc

all: $(check_PROGRAMS)

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/lib/checksrc.pl -D$(srcdir) $(srcdir)/*.c)
