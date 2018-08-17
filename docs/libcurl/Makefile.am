#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = opts

include Makefile.inc

man_DISTMANS = $(man_MANS:.3=.3.dist)

HTMLPAGES = $(man_MANS:.3=.html)

PDFPAGES = $(man_MANS:.3=.pdf)

m4macrodir = $(datadir)/aclocal
dist_m4macro_DATA = libcurl.m4

CLEANFILES = $(HTMLPAGES) $(PDFPAGES) $(TESTS) $(man_DISTMANS) \
  libcurl-symbols.3

EXTRA_DIST = $(man_MANS) ABI symbols-in-versions symbols.pl  \
  mksymbolsmanpage.pl CMakeLists.txt
MAN2HTML= roffit --mandir=. $< >$@

SUFFIXES = .3 .html

libcurl-symbols.3: $(srcdir)/symbols-in-versions $(srcdir)/mksymbolsmanpage.pl
	perl $(srcdir)/mksymbolsmanpage.pl < $(srcdir)/symbols-in-versions > $@

html: $(HTMLPAGES)
	cd opts && $(MAKE) html

.3.html:
	$(MAN2HTML)

pdf: $(PDFPAGES)
	cd opts && $(MAKE) pdf

.3.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

# Make sure each option man page is referenced in the main man page
TESTS = check-easy check-multi
LOG_COMPILER = $(PERL)
# The test fails if the log file contains any text
AM_LOG_FLAGS = -p -e 'die "$$_" if ($$_);'

check-easy: $(srcdir)/curl_easy_setopt.3 $(srcdir)/opts/CURLOPT*.3
	OPTS="$$(ls $(srcdir)/opts/CURLOPT*.3 | $(SED) -e 's,^.*/,,' -e 's,\.3$$,,')" && \
	for opt in $$OPTS; do grep "^\.IP $$opt$$" $(srcdir)/curl_easy_setopt.3 >/dev/null || echo Missing $$opt; done > $@

check-multi: $(srcdir)/curl_multi_setopt.3 $(srcdir)/opts/CURLMOPT*.3
	OPTS="$$(ls $(srcdir)/opts/CURLMOPT*.3 | $(SED) -e 's,^.*/,,' -e 's,\.3$$,,')" && \
	for opt in $$OPTS; do grep "^\.IP $$opt$$" $(srcdir)/curl_multi_setopt.3 >/dev/null || echo Missing $$opt; done > $@
