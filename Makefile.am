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

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

CMAKE_DIST = CMakeLists.txt CMake/CMakeConfigurableFile.in		\
CMake/CurlCheckCSourceCompiles.cmake CMake/CurlCheckCSourceRuns.cmake	\
CMake/CurlTests.c CMake/FindOpenSSL.cmake CMake/FindZLIB.cmake		\
CMake/OtherTests.cmake CMake/Platforms/WindowsCache.cmake		\
CMake/Utilities.cmake include/curl/curlbuild.h.cmake

VC6LIBDSP = vs/vc6/lib/vc6libcurl.dsp
VC6LIBDSPHEAD = vs/t/lib/vc6_libcurl_dsp.head
VC6LIBDSPFOOT = vs/t/lib/vc6_libcurl_dsp.foot

VC8LIBPRJ = vs/vc8/lib/vc8libcurl.vcproj
VC8LIBPRJHEAD = vs/t/lib/vc8_libcurl_prj.head
VC8LIBPRJFOOT = vs/t/lib/vc8_libcurl_prj.foot

VC_DIST = \
 vs/t/README \
 $(VC6LIBDSP) $(VC6LIBDSPHEAD) $(VC6LIBDSPFOOT) \
 $(VC8LIBPRJ) $(VC8LIBPRJHEAD) $(VC8LIBPRJFOOT) \
 vs/vc6/vc6curl.dsw \
 vs/vc6/lib/vc6libcurl.dsw \
 vs/vc6/src/vc6curltool.dsw \
 vs/vc6/src/vc6curltool.dsp

VC6LIBDSP_DEPS = $(VC6LIBDSPHEAD) $(VC6LIBDSPFOOT) \
 Makefile.am lib/Makefile.inc

VC8LIBPRJ_DEPS = $(VC8LIBPRJHEAD) $(VC8LIBPRJFOOT) \
 Makefile.am lib/Makefile.inc

WINBUILD_DIST = winbuild/BUILD.WINDOWS.txt winbuild/gen_resp_file.bat	\
 winbuild/MakefileBuild.vc winbuild/Makefile.vc				\
 winbuild/Makefile.msvc.names

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in	\
 RELEASE-NOTES buildconf libcurl.pc.in MacOSX-Framework	\
 $(CMAKE_DIST) $(VC_DIST) $(WINBUILD_DIST) lib/libcurl.vers.in

CLEANFILES = $(VC6LIBDSP) $(VC8LIBPRJ)

bin_SCRIPTS = curl-config

SUBDIRS = lib src include
DIST_SUBDIRS = $(SUBDIRS) tests packages docs

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurl.pc

# List of libcurl source files required to generate VC IDE dsp and prj files
include lib/Makefile.inc

WIN32SOURCES = $(CSOURCES)
WIN32HEADERS = $(HHEADERS) config-win32.h

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

test-am:
	@(cd tests; $(MAKE) all am-test)

endif

examples:
	@(cd docs/examples; $(MAKE) check)

# This is a hook to have 'make clean' also clean up the docs and the tests
# dir. The extra check for the Makefiles being present is necessary because
# 'make distcheck' will make clean first in these directories _before_ it runs
# this hook.
clean-local:
	@(if test -f tests/Makefile; then cd tests; $(MAKE) clean; fi)
	@(if test -f docs/Makefile; then cd docs; $(MAKE) clean; fi)

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

.PHONY: vc6-ide

vc6-ide:
	$(MAKE) $(VC6LIBDSP)

$(VC6LIBDSP): $(VC6LIBDSP_DEPS)
	@(echo "generating '$(VC6LIBDSP)'"; \
	\
	for dir in 'vs' 'vs/vc6' 'vs/vc6/lib'; do \
	  test -d "$$dir" || mkdir "$$dir" || exit 1; \
	done; \
	\
	dir='..\..\..\lib\'; \
	body='$(VC6LIBDSP)'.body; \
	win32_srcs='$(WIN32SOURCES)'; \
	win32_hdrs='$(WIN32HEADERS)'; \
	sorted_srcs=`for file in $$win32_srcs; do echo $$file; done | sort`; \
	sorted_hdrs=`for file in $$win32_hdrs; do echo $$file; done | sort`; \
	\
	echo "# Begin Group \"Source Files\""  > $$body; \
	echo ""                               >> $$body; \
	echo "# PROP Default_Filter \"\""     >> $$body; \
	for file in $$sorted_srcs; do \
	  echo "# Begin Source File"          >> $$body; \
	  echo ""                             >> $$body; \
	  echo "SOURCE="$$dir$$file           >> $$body; \
	  echo "# End Source File"            >> $$body; \
	done; \
	echo "# End Group"                    >> $$body; \
	echo "# Begin Group \"Header Files\"" >> $$body; \
	echo ""                               >> $$body; \
	echo "# PROP Default_Filter \"\""     >> $$body; \
	for file in $$sorted_hdrs; do \
	  echo "# Begin Source File"          >> $$body; \
	  echo ""                             >> $$body; \
	  echo "SOURCE="$$dir$$file           >> $$body; \
	  echo "# End Source File"            >> $$body; \
	done; \
	echo "# End Group"                    >> $$body; \
	\
	awk '{ printf("%s\r\n", $$0); }' \
	  $(srcdir)/$(VC6LIBDSPHEAD) $$body $(srcdir)/$(VC6LIBDSPFOOT) \
	  > $(VC6LIBDSP) || { rm -f $$body; exit 1; }; \
	\
	rm -f $$body)

.PHONY: vc8-ide

vc8-ide:
	$(MAKE) $(VC8LIBPRJ)

$(VC8LIBPRJ): $(VC8LIBPRJ_DEPS)
	@(echo "generating '$(VC8LIBPRJ)'"; \
	\
	for dir in 'vs' 'vs/vc8' 'vs/vc8/lib'; do \
	  test -d "$$dir" || mkdir "$$dir" || exit 1; \
	done; \
	\
	dir='..\..\..\lib\'; \
	body='$(VC8LIBPRJ)'.body; \
	win32_srcs='$(WIN32SOURCES)'; \
	win32_hdrs='$(WIN32HEADERS)'; \
	sorted_srcs=`for file in $$win32_srcs; do echo $$file; done | sort`; \
	sorted_hdrs=`for file in $$win32_hdrs; do echo $$file; done | sort`; \
	\
	echo "%tab%%tab%<Filter Name=\"Source Files\">"  > $$body; \
	for file in $$sorted_srcs; do \
	  echo "%tab%%tab%%tab%<File RelativePath=\""$$dir$$file"\"></File>" >> $$body; \
	done; \
	echo "%tab%%tab%</Filter>"                      >> $$body; \
	echo "%tab%%tab%<Filter Name=\"Header Files\">" >> $$body; \
	for file in $$sorted_hdrs; do \
	  echo "%tab%%tab%%tab%<File RelativePath=\""$$dir$$file"\"></File>" >> $$body; \
	done; \
	echo "%tab%%tab%</Filter>"                      >> $$body; \
	\
	awk '{ gsub(/%tab%/, "\t"); printf("%s\r\n", $$0); }' \
	  $(srcdir)/$(VC8LIBPRJHEAD) $$body $(srcdir)/$(VC8LIBPRJFOOT) \
	  > $(VC8LIBPRJ) || { rm -f $$body; exit 1; }; \
	\
	rm -f $$body)

