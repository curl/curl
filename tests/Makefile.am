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

HTMLPAGES = testcurl.html runtests.html
PDFPAGES = testcurl.pdf runtests.pdf
MANDISTPAGES = runtests.1.dist testcurl.1.dist

EXTRA_DIST = appveyor.pm azure.pm badsymbols.pl check-deprecated.pl CMakeLists.txt \
 dictserver.py directories.pm disable-scan.pl error-codes.pl extern-scan.pl \
 FILEFORMAT.md ftp.pm ftpserver.pl getpart.pm http-server.pl http2-server.pl http3-server.pl \
 manpage-scan.pl manpage-syntax.pl markdown-uppercase.pl mem-include-scan.pl \
 memanalyze.pl negtelnetserver.py nroff-scan.pl option-check.pl options-scan.pl \
 pathhelp.pm README.md rtspserver.pl runtests.1 runtests.pl secureserver.pl \
 serverhelp.pm smbserver.py sshhelp.pm sshserver.pl stunnel.pem symbol-scan.pl \
 testcurl.1 testcurl.pl tftpserver.pl util.py valgrind.pm valgrind.supp version-scan.pl 

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

SUBDIRS = certs data server libtest http $(BUILD_UNIT)
DIST_SUBDIRS = $(SUBDIRS) $(DIST_UNIT)

PERLFLAGS = -I$(srcdir)

CLEANFILES = .http.pid .https.pid .ftp.pid .ftps.pid $(MANDISTPAGES)

MAN2HTML= roffit $< >$@

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
TEST_E = -a -e

# !flaky means that it'll skip all tests using the flaky keyword
TEST_NF = -a -p !flaky

# special CI target derived from nonflaky with CI-specific flags
TEST_CI = $(TEST_NF) -rm
endif

# make sure that PERL is pointing to an executable
perlcheck:
	@if ! test -x "$(PERL)"; then echo "No perl!"; exit 2; fi

test: perlcheck all
	$(TEST) $(TFLAGS)

quiet-test: perlcheck all
	$(TEST) $(TEST_Q) $(TFLAGS)

am-test: perlcheck all
	$(TEST) $(TEST_AM) $(TFLAGS)

ci-test: perlcheck all
	$(TEST) $(TEST_CI) $(TFLAGS)

full-test: perlcheck all
	$(TEST) $(TEST_F) $(TFLAGS)

nonflaky-test: perlcheck all
	$(TEST) $(TEST_NF) $(TFLAGS)

torture-test: perlcheck all
	$(TEST) $(TEST_T) $(TFLAGS)

event-test: perlcheck all
	$(TEST) $(TEST_E) $(TFLAGS)

.1.html:
	$(MAN2HTML)

.1.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

checksrc:
	cd libtest && $(MAKE) checksrc
	cd unit && $(MAKE) checksrc
	cd server && $(MAKE) checksrc

if CURLDEBUG
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif
