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
#***************************************************************************
ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = foreign nostdinc

SUBDIRS = . tests

AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src $(OPENSSL_CFLAGS)
AM_CFLAGS = $(WARN_CFLAGS)

CSOURCES = \
 src/mock_sspi.c \
 src/mock_win32.c \
 src/mock_compat.c \
 src/mock_crypto.c \
 src/mock_x509.c \
 src/mock_hash.c

HHEADERS = \
 include/curl_win32.h \
 include/ntsecapi.h \
 include/schannel.h \
 include/security.h \
 include/sspi.h \
 include/subauth.h \
 include/wincrypt.h \
 include/windows.h

EXTRA_DIST = \
  CMakeLists.txt \
  README.md \
  autogen.sh \
  schannel-mockup.pc.in

lib_LTLIBRARIES = libschannelmockup.la

libschannelmockup_la_SOURCES = $(CSOURCES) $(HHEADERS)
libschannelmockup_la_CPPFLAGS = $(AM_CPPFLAGS)
libschannelmockup_la_CFLAGS = $(AM_CFLAGS)
libschannelmockup_la_LIBADD = $(OPENSSL_LIBS)
libschannelmockup_la_LDFLAGS = -no-undefined

include_HEADERS = $(HHEADERS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = schannel-mockup.pc

checksrc:
	@if test -f $(srcdir)/../../scripts/checksrc.pl; then \
	  echo "  RUN      checksrc"; \
	  $(PERL) $(srcdir)/../../scripts/checksrc.pl -D$(srcdir) $(CSOURCES) $(HHEADERS); \
	fi
	$(MAKE) -C tests checksrc

test: check
