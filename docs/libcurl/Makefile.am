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

AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = opts

if BUILD_DOCS
# Get man_MANS variable
include Makefile.inc

CURLPAGES = $(man_MANS:.3=.md)
endif

m4macrodir = $(datadir)/aclocal
dist_m4macro_DATA = libcurl.m4

CLEANFILES = $(man_MANS) libcurl-symbols.md

EXTRA_DIST = $(CURLPAGES) ABI.md symbols-in-versions symbols.pl  \
  mksymbolsmanpage.pl CMakeLists.txt

if BUILD_DOCS

CD2NROFF = $(top_srcdir)/scripts/cd2nroff $< >$@
CD2 = $(CD2_$(V))
CD2_0 = @echo "  RENDER " $@;
CD2_1 =
CD2_ = $(CD2_0)

SUFFIXES = .3 .md

libcurl-symbols.md: $(srcdir)/symbols-in-versions $(srcdir)/mksymbolsmanpage.pl
	$(CD2)perl $(srcdir)/mksymbolsmanpage.pl < $(srcdir)/symbols-in-versions > $@

.md.3:
	$(CD2)$(CD2NROFF)

endif
