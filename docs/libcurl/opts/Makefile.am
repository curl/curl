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
# SPDX-License-Identifier: curl
#
###########################################################################

AUTOMAKE_OPTIONS = foreign no-dependencies

include Makefile.inc

man_DISTMANS = $(man_MANS:.3=.3.dist)

HTMLPAGES = $(man_MANS:.3=.html)

PDFPAGES = $(man_MANS:.3=.pdf)

CLEANFILES = $(HTMLPAGES) $(PDFPAGES) $(man_DISTMANS)

EXTRA_DIST = $(man_MANS) CMakeLists.txt
MAN2HTML= roffit --mandir=. $< >$@

SUFFIXES = .3 .html

html: $(HTMLPAGES)

.3.html:
	$(MAN2HTML)

pdf: $(PDFPAGES)

.3.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

mancheck:
	@cd $(top_srcdir)/docs/libcurl/opts && ls `awk -F, '!/OBSOLETE/ && /^  CINIT/ { a=substr($$1, 9); print "CURLOPT_" a ".3"}' $(top_srcdir)/include/curl/curl.h`
	rm -f in_temp
	@(for a in $(man_MANS); do echo $$a >>in_temp; done)
	sort in_temp > in_makefile
	ls CURL*.3 > in_directory
	-diff -u in_makefile in_directory
	rm in_temp in_directory in_makefile
