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

AUTOMAKE_OPTIONS = foreign no-dependencies

man_MANS = curl.1 curl-config.1
GENHTMLPAGES = curl.html curl-config.html
PDFPAGES = curl.pdf curl-config.pdf

HTMLPAGES = $(GENHTMLPAGES) index.html

SUBDIRS = examples libcurl

CLEANFILES = $(GENHTMLPAGES) $(PDFPAGES)

EXTRA_DIST = MANUAL BUGS CONTRIBUTE FAQ FEATURES INTERNALS SSLCERTS	 \
 README.win32 RESOURCES TODO TheArtOfHttpScripting THANKS VERSIONS	 \
 KNOWN_BUGS BINDINGS $(man_MANS) $(HTMLPAGES) HISTORY INSTALL		 \
 $(PDFPAGES) LICENSE-MIXING README.netware DISTRO-DILEMMA INSTALL.devcpp \
 MAIL-ETIQUETTE

MAN2HTML= roffit < $< >$@

SUFFIXES = .1 .html .pdf

html: $(HTMLPAGES)
	cd libcurl; make html

pdf: $(PDFPAGES)
	cd libcurl; make pdf

.1.html:
	$(MAN2HTML)

.1.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

