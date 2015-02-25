#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

HTMLPAGES = testcurl.html runtests.html
PDFPAGES = testcurl.pdf runtests.pdf

EXTRA_DIST = ftpserver.pl httpserver.pl secureserver.pl runtests.pl getpart.pm \
 FILEFORMAT README stunnel.pem memanalyze.pl testcurl.pl valgrind.pm ftp.pm   \
 sshserver.pl sshhelp.pm testcurl.1 runtests.1 $(HTMLPAGES) $(PDFPAGES) \
 serverhelp.pm tftpserver.pl rtspserver.pl directories.pm symbol-scan.pl \
 CMakeLists.txt mem-include-scan.pl valgrind.supp http_pipe.py extern-scan.pl

DISTCLEANFILES = configurehelp.pm

# we have two variables here to make sure DIST_SUBDIRS won't get 'unit'
# added twice as then targets such as 'distclean' misbehave and try to
# do things twice in that subdir at times (and thus fails).
if BUILD_UNITTESTS
BUILD_UNIT = unit
DIST_UNIT =
else
BUILD_UNIT =
DIST_UNIT = unit
endif

SUBDIRS = certs data server libtest $(BUILD_UNIT)
DIST_SUBDIRS = $(SUBDIRS) $(DIST_UNIT)

PERLFLAGS = -I$(srcdir)

CLEANFILES = .http.pid .https.pid .ftp.pid .ftps.pid

MAN2HTML= roffit < $< >$@

curl:
	@cd $(top_builddir) && $(MAKE)

if CROSSCOMPILING
TEST = @echo "NOTICE: we can't run the tests when cross-compiling!"
else # if not cross-compiling:
TEST = srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl
TEST_Q = -a -s
TEST_AM = -a -am
TEST_F = -a -p -r
TEST_T = -a -t
endif

# make sure that PERL is pointing to an executable
perlcheck:
	@if ! test -x "$(PERL)"; then echo "No perl!"; exit 2; fi

test: perlcheck all
	$(TEST)

quiet-test: perlcheck all
	$(TEST) $(TEST_Q)

am-test: perlcheck all
	$(TEST) $(TEST_AM)

full-test: perlcheck all
	$(TEST) $(TEST_F)

torture-test: perlcheck all
	$(TEST) $(TEST_T)

.1.html:
	$(MAN2HTML)

.1.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")
