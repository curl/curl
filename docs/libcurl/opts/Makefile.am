#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

man_MANS = CURLOPT_HEADER.3 CURLOPT_IOCTLFUNCTION.3 CURLOPT_NOPROGRESS.3	\
 CURLOPT_NOSIGNAL.3 CURLOPT_READDATA.3 CURLOPT_READFUNCTION.3			\
 CURLOPT_VERBOSE.3 CURLOPT_WILDCARDMATCH.3 CURLOPT_WRITEDATA.3			\
 CURLOPT_WRITEFUNCTION.3

HTMLPAGES =  CURLOPT_HEADER.html CURLOPT_IOCTLFUNCTION.html CURLOPT_NOPROGRESS.html	\
 CURLOPT_NOSIGNAL.html CURLOPT_READDATA.html CURLOPT_READFUNCTION.html			\
 CURLOPT_VERBOSE.html CURLOPT_WILDCARDMATCH.html CURLOPT_WRITEDATA.html			\
 CURLOPT_WRITEFUNCTION.html

PDFPAGES =  CURLOPT_HEADER.pdf CURLOPT_IOCTLFUNCTION.pdf CURLOPT_NOPROGRESS.pdf	\
 CURLOPT_NOSIGNAL.pdf CURLOPT_READDATA.pdf CURLOPT_READFUNCTION.pdf			\
 CURLOPT_VERBOSE.pdf CURLOPT_WILDCARDMATCH.pdf CURLOPT_WRITEDATA.pdf			\
 CURLOPT_WRITEFUNCTION.pdf

CLEANFILES = $(HTMLPAGES) $(PDFPAGES)

EXTRA_DIST = $(man_MANS) $(HTMLPAGES) $(PDFPAGES)
MAN2HTML= roffit --mandir=. < $< >$@

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
	ls `awk -F, '/^  CINIT/ { a=substr($$1, 9); print "CURLOPT_" a ".3"}' $(top_srcdir)/include/curl/curl.h`