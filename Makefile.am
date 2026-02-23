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

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

CMAKE_DIST =                                     \
  CMake/cmake_uninstall.in.cmake                 \
  CMake/curl-config.in.cmake                     \
  CMake/CurlSymbolHiding.cmake                   \
  CMake/CurlTests.c                              \
  CMake/FindBrotli.cmake                         \
  CMake/FindCares.cmake                          \
  CMake/FindGnuTLS.cmake                         \
  CMake/FindGSS.cmake                            \
  CMake/FindLDAP.cmake                           \
  CMake/FindLibbacktrace.cmake                   \
  CMake/FindLibgsasl.cmake                       \
  CMake/FindLibidn2.cmake                        \
  CMake/FindLibpsl.cmake                         \
  CMake/FindLibrtmp.cmake                        \
  CMake/FindLibssh.cmake                         \
  CMake/FindLibssh2.cmake                        \
  CMake/FindLibuv.cmake                          \
  CMake/FindMbedTLS.cmake                        \
  CMake/FindNGHTTP2.cmake                        \
  CMake/FindNGHTTP3.cmake                        \
  CMake/FindNGTCP2.cmake                         \
  CMake/FindNettle.cmake                         \
  CMake/FindQuiche.cmake                         \
  CMake/FindRustls.cmake                         \
  CMake/FindWolfSSL.cmake                        \
  CMake/FindZstd.cmake                           \
  CMake/Macros.cmake                             \
  CMake/OtherTests.cmake                         \
  CMake/PickyWarnings.cmake                      \
  CMake/Utilities.cmake                          \
  CMake/unix-cache.cmake                         \
  CMake/win32-cache.cmake                        \
  CMakeLists.txt                                 \
  tests/cmake/CMakeLists.txt                     \
  tests/cmake/test.c                             \
  tests/cmake/test.cpp                           \
  tests/cmake/test.sh

EXTRA_DIST = CHANGES.md COPYING RELEASE-NOTES Dockerfile .clang-tidy.yml .editorconfig $(CMAKE_DIST)

DISTCLEANFILES = buildinfo.txt

bin_SCRIPTS = curl-config

SUBDIRS = lib docs src scripts
DIST_SUBDIRS = $(SUBDIRS) tests projects include docs

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurl.pc

dist-hook:
	rm -rf $(top_builddir)/tests/log
	find $(distdir) -name "*.dist" -exec rm -- {} \;
	(distit=`find $(srcdir) -name "*.dist" | grep -v Makefile`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp -p $$file $(distdir)$$strip; \
	done)

check: test examples check-docs

if CROSSCOMPILING
test-full: test
test-nonflaky: test
test-torture: test
test-event: test
test-am: test
test-ci: test
pytest: test
pytest-ci: test

test:
	@echo "NOTICE: we cannot run the tests when cross-compiling!"

else

test:
	@(cd tests; $(MAKE) all quiet-test)

test-full:
	@(cd tests; $(MAKE) all full-test)

test-nonflaky:
	@(cd tests; $(MAKE) all nonflaky-test)

test-torture:
	@(cd tests; $(MAKE) all torture-test)

test-event:
	@(cd tests; $(MAKE) all event-test)

test-am:
	@(cd tests; $(MAKE) all am-test)

test-ci:
	@(cd tests; $(MAKE) all ci-test)

pytest:
	@(cd tests; $(MAKE) all default-pytest)

pytest-ci:
	@(cd tests; $(MAKE) all ci-pytest)

endif

examples:
	@(cd docs/examples; $(MAKE) check)

check-docs:
	@(cd docs/libcurl; $(MAKE) check)

# We extend the standard install with a custom hook:
if BUILD_DOCS
install-data-hook:
	(cd include && $(MAKE) install)
	(cd docs && $(MAKE) install)
	(cd docs/libcurl && $(MAKE) install)
else
install-data-hook:
	(cd include && $(MAKE) install)
	(cd docs && $(MAKE) install)
endif

# We extend the standard uninstall with a custom hook:
uninstall-hook:
	(cd include && $(MAKE) uninstall)
	(cd docs && $(MAKE) uninstall)
	(cd docs/libcurl && $(MAKE) uninstall)

ca-bundle: $(srcdir)/scripts/mk-ca-bundle.pl
	@echo "generating a fresh ca-bundle.crt"
	@perl $(srcdir)/scripts/mk-ca-bundle.pl -b -l -u lib/ca-bundle.crt

ca-firefox: $(srcdir)/scripts/firefox-db2pem.sh
	@echo "generating a fresh ca-bundle.crt"
	$(srcdir)/scripts/firefox-db2pem.sh lib/ca-bundle.crt

checksrc:
	(cd lib && $(MAKE) checksrc)
	(cd src && $(MAKE) checksrc)
	(cd tests && $(MAKE) checksrc)
	(cd include/curl && $(MAKE) checksrc)
	(cd docs/examples && $(MAKE) checksrc)
	(cd projects && $(MAKE) checksrc)

lint: checksrc
	@PERL@ $(top_srcdir)/scripts/spacecheck.pl

tidy:
	(cd src && $(MAKE) tidy)
	(cd lib && $(MAKE) tidy)

clean-local:
	(cd tests && $(MAKE) clean)
