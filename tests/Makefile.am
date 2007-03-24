#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# $Id$
###########################################################################

HTMLPAGES = testcurl.html runtests.html
PDFPAGES = testcurl.pdf runtests.pdf

EXTRA_DIST = ftpserver.pl httpserver.pl httpsserver.pl runtests.pl getpart.pm \
 FILEFORMAT README stunnel.pem memanalyze.pl testcurl.pl valgrind.pm ftp.pm   \
 sshserver.pl testcurl.1 runtests.1 $(HTMLPAGES) $(PDFPAGES)

SUBDIRS = data server libtest

PERLFLAGS = -I$(srcdir)

CLEANFILES = .http.pid .https.pid .ftp.pid .ftps.pid

MAN2HTML= roffit < $< >$@

curl:
	@cd $(top_builddir) && $(MAKE)

if CROSSCOMPILING
TEST = @echo "NOTICE: we can't run the tests when cross-compiling!"
TEST_Q =
TEST_F =
TEST_T =
else # if not cross-compiling:
TEST = srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl
TEST_Q = -s -a
TEST_F = -a -p
TEST_T = -t
endif

test: all
	$(TEST)

quiet-test: all
	$(TEST) $(TEST_Q)

full-test: all
	$(TEST) $(TEST_F)

torture-test: all
	$(TEST) $(TEST_T)

.1.html:
	$(MAN2HTML)

.1.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")
