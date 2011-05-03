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

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

CMAKE_DIST = CMakeLists.txt CMake/CMakeConfigurableFile.in		\
CMake/CurlCheckCSourceCompiles.cmake CMake/CurlCheckCSourceRuns.cmake	\
CMake/CurlTests.c CMake/FindOpenSSL.cmake CMake/FindZLIB.cmake		\
CMake/OtherTests.cmake CMake/Platforms/WindowsCache.cmake		\
CMake/Utilities.cmake include/curl/curlbuild.h.cmake

WINBUILD_DIST = winbuild/BUILD.WINDOWS.txt winbuild/gen_resp_file.bat	\
winbuild/MakefileBuild.vc winbuild/Makefile.vc

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in	\
 curl-style.el sample.emacs RELEASE-NOTES buildconf 	\
 libcurl.pc.in vc6curl.dsw MacOSX-Framework Android.mk $(CMAKE_DIST)	\
 Makefile.msvc.names $(WINBUILD_DIST)

bin_SCRIPTS = curl-config

SUBDIRS = lib src include
DIST_SUBDIRS = $(SUBDIRS) tests packages docs

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurl.pc

dist-hook:
	rm -rf $(top_builddir)/tests/log
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist" | grep -v ./ares/`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)

html:
	cd docs; make html

pdf:
	cd docs; make pdf

check: test examples

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

test-torture:
	@(cd tests; $(MAKE) all torture-test)

endif

examples:
	@(cd docs/examples; $(MAKE) check)

clean-local:
	@(cd tests; $(MAKE) clean)
	@(cd docs; $(MAKE) clean)

#
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

# gak - libtool requires an absoulte directory, hence the pwd below...
pkgadd:
	umask 022 ; \
	make install DESTDIR=`/bin/pwd`/packages/Solaris/root ; \
	cat COPYING > $(srcdir)/packages/Solaris/copyright ; \
	cd $(srcdir)/packages/Solaris && $(MAKE) package

#
# Build a cygwin binary tarball installation file
# resulting .tar.bz2 file will end up at packages/Win32/cygwin
cygwinbin:
	$(MAKE) -C packages/Win32/cygwin cygwinbin

# We extend the standard install with a custom hook:
install-data-hook:
	cd include && $(MAKE) install
	cd docs && $(MAKE) install

# We extend the standard uninstall with a custom hook:
uninstall-hook:
	cd include && $(MAKE) uninstall
	cd docs && $(MAKE) uninstall

ca-bundle: lib/mk-ca-bundle.pl
	@echo "generate a fresh ca-bundle.crt"
	@perl $< -b -l -u lib/ca-bundle.crt

ca-firefox: lib/firefox-db2pem.sh
	@echo "generate a fresh ca-bundle.crt"
	./lib/firefox-db2pem.sh lib/ca-bundle.crt

checksrc:
	cd lib && $(MAKE) checksrc
	cd src && $(MAKE) checksrc
