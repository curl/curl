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

CMAKE_DIST =                                    \
 CMake/cmake_uninstall.cmake.in                 \
 CMake/CMakeConfigurableFile.in                 \
 CMake/curl-config.cmake.in                     \
 CMake/CurlSymbolHiding.cmake                   \
 CMake/CurlTests.c                              \
 CMake/FindBearSSL.cmake                        \
 CMake/FindBrotli.cmake                         \
 CMake/FindCARES.cmake                          \
 CMake/FindGSS.cmake                            \
 CMake/FindLibPSL.cmake                         \
 CMake/FindLibSSH2.cmake                        \
 CMake/FindMbedTLS.cmake                        \
 CMake/FindMSH3.cmake                           \
 CMake/FindNGHTTP2.cmake                        \
 CMake/FindNGHTTP3.cmake                        \
 CMake/FindNGTCP2.cmake                         \
 CMake/FindQUICHE.cmake                         \
 CMake/FindWolfSSL.cmake                        \
 CMake/FindZstd.cmake                           \
 CMake/Macros.cmake                             \
 CMake/OtherTests.cmake                         \
 CMake/PickyWarnings.cmake                      \
 CMake/Platforms/WindowsCache.cmake             \
 CMake/Utilities.cmake                          \
 CMakeLists.txt

VC_DIST = projects/README.md                           \
 projects/build-openssl.bat                            \
 projects/build-wolfssl.bat                            \
 projects/checksrc.bat                                 \
 projects/generate.bat                                 \
 projects/wolfssl_options.h                            \
 projects/wolfssl_override.props

WINBUILD_DIST = winbuild/README.md winbuild/gen_resp_file.bat \
 winbuild/MakefileBuild.vc winbuild/Makefile.vc winbuild/makedebug.bat

PLAN9_DIST = plan9/include/mkfile \
 plan9/include/mkfile             \
 plan9/mkfile.proto               \
 plan9/mkfile                     \
 plan9/README                     \
 plan9/lib/mkfile.inc             \
 plan9/lib/mkfile                 \
 plan9/src/mkfile.inc             \
 plan9/src/mkfile

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in       \
 RELEASE-NOTES buildconf libcurl.pc.in $(CMAKE_DIST) $(VC_DIST)         \
 $(WINBUILD_DIST) $(PLAN9_DIST) lib/libcurl.vers.in buildconf.bat       \
 libcurl.def Dockerfile

CLEANFILES = $(VC14_LIBVCXPROJ) $(VC14_SRCVCXPROJ) \
 $(VC14_10_LIBVCXPROJ) $(VC14_10_SRCVCXPROJ)       \
 $(VC14_20_LIBVCXPROJ) $(VC14_20_SRCVCXPROJ)       \
 $(VC14_30_LIBVCXPROJ) $(VC14_30_SRCVCXPROJ)

bin_SCRIPTS = curl-config

SUBDIRS = lib docs src scripts
DIST_SUBDIRS = $(SUBDIRS) tests packages scripts include docs

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurl.pc

# List of files required to generate VC IDE .dsp, .vcproj and .vcxproj files
include lib/Makefile.inc
include src/Makefile.inc

dist-hook:
	rm -rf $(top_builddir)/tests/log
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist" | grep -v ./ares/`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp -p $$file $(distdir)$$strip; \
	done)

check: test examples check-docs

if CROSSCOMPILING
test-full: test
test-torture: test

test:
	@echo "NOTICE: we can't run the tests when cross-compiling!"

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

endif

examples:
	@(cd docs/examples; $(MAKE) check)

check-docs:
	@(cd docs/libcurl; $(MAKE) check)

# Build source and binary rpms. For rpm-3.0 and above, the ~/.rpmmacros
# must contain the following line:
# %_topdir /home/loic/local/rpm
# and that /home/loic/local/rpm contains the directory SOURCES, BUILD etc.
#
# cd /home/loic/local/rpm ; mkdir -p SOURCES BUILD RPMS/i386 SPECS SRPMS
#
# If additional configure flags are needed to build the package, add the
# following in ~/.rpmmacros
# %configure CFLAGS="%{optflags}" ./configure %{_target_platform} --prefix=%{_prefix} ${AM_CONFIGFLAGS}
# and run make rpm in the following way:
# AM_CONFIGFLAGS='--with-uri=/home/users/loic/local/RedHat-6.2' make rpm
#

rpms:
	$(MAKE) RPMDIST=curl rpm
	$(MAKE) RPMDIST=curl-ssl rpm

rpm:
	RPM_TOPDIR=`rpm --showrc | $(PERL) -n -e 'print if(s/.*_topdir\s+(.*)/$$1/)'` ; \
	cp $(srcdir)/packages/Linux/RPM/$(RPMDIST).spec $$RPM_TOPDIR/SPECS ; \
	cp $(PACKAGE)-$(VERSION).tar.gz $$RPM_TOPDIR/SOURCES ; \
	rpm -ba --clean --rmsource $$RPM_TOPDIR/SPECS/$(RPMDIST).spec ; \
	mv $$RPM_TOPDIR/RPMS/i386/$(RPMDIST)-*.rpm . ; \
	mv $$RPM_TOPDIR/SRPMS/$(RPMDIST)-*.src.rpm .

#
# Build a Solaris pkgadd format file
# run 'make pkgadd' once you've done './configure' and 'make' to make a Solaris pkgadd format
# file (which ends up back in this directory).
# The pkgadd file is in 'pkgtrans' format, so to install on Solaris, do
# pkgadd -d ./HAXXcurl-*
#

# gak - libtool requires an absolute directory, hence the pwd below...
pkgadd:
	umask 022 ; \
	$(MAKE) install DESTDIR=`/bin/pwd`/packages/Solaris/root ; \
	cat COPYING > $(srcdir)/packages/Solaris/copyright ; \
	cd $(srcdir)/packages/Solaris && $(MAKE) package

#
# Build a cygwin binary tarball installation file
# resulting .tar.bz2 file will end up at packages/Win32/cygwin
cygwinbin:
	$(MAKE) -C packages/Win32/cygwin cygwinbin

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
	(cd packages && $(MAKE) checksrc)

tidy:
	(cd src && $(MAKE) tidy)
	(cd lib && $(MAKE) tidy)
