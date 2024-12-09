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

if BUILD_DOCS
# if we disable man page building, ignore these
RUNTESTS_DOCS = runtests.1
TESTCURL_DOCS = testcurl.1
MANFILES = $(RUNTESTS_DOCS) $(TESTCURL_DOCS)
endif

CURLPAGES = runtests.md testcurl.md

# scripts used in test cases
TESTSCRIPTS = \
 test1119.pl  \
 test1132.pl  \
 test1135.pl  \
 test1139.pl  \
 test1140.pl  \
 test1165.pl  \
 test1167.pl  \
 test1173.pl  \
 test1175.pl  \
 test1177.pl  \
 test1222.pl  \
 test1275.pl  \
 test1276.pl  \
 test1477.pl  \
 test1486.pl  \
 test1488.pl  \
 test1544.pl  \
 test1707.pl  \
 test971.pl

EXTRA_DIST =        \
 CMakeLists.txt     \
 FILEFORMAT.md      \
 README.md          \
 appveyor.pm        \
 azure.pm           \
 devtest.pl         \
 dictserver.py      \
 directories.pm     \
 ech_combos.py      \
 ech_tests.sh       \
 ftpserver.pl       \
 getpart.pm         \
 globalconfig.pm    \
 http-server.pl     \
 http2-server.pl    \
 http3-server.pl    \
 memanalyze.pl      \
 mk-bundle-hints.sh \
 mk-bundle.pl       \
 negtelnetserver.py \
 nghttpx.conf       \
 pathhelp.pm        \
 processhelp.pm     \
 requirements.txt   \
 rtspserver.pl      \
 runner.pm          \
 runtests.pl        \
 secureserver.pl    \
 serverhelp.pm      \
 servers.pm         \
 smbserver.py       \
 sshhelp.pm         \
 sshserver.pl       \
 stunnel.pem        \
 testcurl.pl        \
 testutil.pm        \
 tftpserver.pl      \
 util.py            \
 valgrind.pm        \
 valgrind.supp      \
 $(TESTSCRIPTS)     \
 $(CURLPAGES)

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

curl:
	@cd $(top_builddir) && $(MAKE)

TEST_COMMON =

if CROSSCOMPILING
TEST = @echo "NOTICE: we can't run the tests when cross-compiling!"
PYTEST = $(TEST)
else # if not cross-compiling:
if USE_TEST_BUNDLES
TEST_COMMON += -bundle
endif

if BUILD_DOCS
else
TEST_COMMON += !documentation
endif

TEST = srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl $(TEST_COMMON)
TEST_Q = -a -s
TEST_AM = -a -am
TEST_F = -a -p -r
TEST_T = -a -t -j20
TEST_E = -a -e

# ~<keyword> means that it will run all tests matching the keyword, but will
# ignore their results (since these ones are likely to fail for no good reason)
TEST_NF = -a -p ~flaky ~timing-dependent

# special CI target derived from nonflaky with CI-specific flags
TEST_CI = $(TEST_NF) -r -rm -j20

PYTEST = pytest
endif

CD2NROFF = $(top_srcdir)/scripts/cd2nroff $< >$@

SUFFIXES = .1 .md

.md.1:
	$(CD2)$(CD2NROFF)

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

default-pytest: ci-pytest

ci-pytest: all
	srcdir=$(srcdir) $(PYTEST) -v $(srcdir)/http

checksrc:
	(cd libtest && $(MAKE) checksrc)
	(cd unit && $(MAKE) checksrc)
	(cd server && $(MAKE) checksrc)
	(cd http && $(MAKE) checksrc)

all-local: $(MANFILES)

distclean:
	rm -f $(MANFILES)
