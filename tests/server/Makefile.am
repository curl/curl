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
# $(top_srcdir)/src for "tool_binmode.h", "tool_xattr.h"

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/src            \
              -I$(top_srcdir)/tests/server

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

CFLAGS += @CURL_CFLAG_EXTRAS@

if DOING_NATIVE_WINDOWS
AM_CPPFLAGS += -DCURL_STATICLIB
endif
if ENABLE_SERVER_DEBUG
if DEBUGBUILD
AM_CPPFLAGS += -DDEBUGBUILD
endif
if CURLDEBUG
AM_CPPFLAGS += -DCURLDEBUG
endif
endif

# Makefile.inc provides neat definitions
include Makefile.inc

EXTRA_DIST = CMakeLists.txt .checksrc mk-bundle.pl $(FIRSTFILES)

if USE_TEST_BUNDLES
server_EXCLUDE =
if ENABLE_SERVER_DEBUG
if CURLDEBUG
server_EXCLUDE += $(MEMDEBUG)
endif
endif
server_bundle.c: $(top_srcdir)/tests/server/mk-bundle.pl $(MEMDEBUG) $(CURLX_SRCS) $(USEFUL) $(INET_PTON) $(UTIL) $(FIRSTFILES)
	@PERL@ $(top_srcdir)/tests/server/mk-bundle.pl $(MEMDEBUG) $(CURLX_SRCS) $(USEFUL) $(INET_PTON) $(UTIL) $(SERVERPROGS) --exclude $(server_EXCLUDE) > server_bundle.c

noinst_PROGRAMS = servers
nodist_servers_SOURCES = server_bundle.c
servers_SOURCES = $(server_EXCLUDE)
servers_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
servers_CFLAGS = $(AM_CFLAGS)
CLEANFILES = server_bundle.c
else
noinst_PROGRAMS = $(SERVERPROGS)
endif

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	  -W$(srcdir)/server_bundle.c \
	  $(srcdir)/*.[ch])

if DEBUGBUILD
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif
