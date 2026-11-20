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
AUTOMAKE_OPTIONS = foreign nostdinc

AM_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_CFLAGS)
AM_CFLAGS = $(WARN_CFLAGS)

LDADD = ../libschannelmockup.la $(OPENSSL_LIBS)

check_PROGRAMS = test_credentials test_sspi_handshake test_encrypt_decrypt test_crypto_store

TESTS = $(check_PROGRAMS)

test_credentials_SOURCES = test_credentials.c
test_sspi_handshake_SOURCES = test_sspi_handshake.c
test_encrypt_decrypt_SOURCES = test_encrypt_decrypt.c
test_crypto_store_SOURCES = test_crypto_store.c

all-local: $(check_PROGRAMS)

test: check

checksrc:
	@if test -f $(top_srcdir)/../../scripts/checksrc.pl; then \
	  echo "  RUN      checksrc in tests"; \
	  $(PERL) $(top_srcdir)/../../scripts/checksrc.pl -D$(srcdir) test_credentials.c test_sspi_handshake.c test_encrypt_decrypt.c test_crypto_store.c; \
	fi
