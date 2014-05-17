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

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

CMAKE_DIST = CMakeLists.txt CMake/CMakeConfigurableFile.in		\
CMake/CurlCheckCSourceCompiles.cmake CMake/CurlCheckCSourceRuns.cmake	\
CMake/CurlTests.c CMake/FindOpenSSL.cmake CMake/FindZLIB.cmake		\
CMake/OtherTests.cmake CMake/Platforms/WindowsCache.cmake		\
CMake/Utilities.cmake include/curl/curlbuild.h.cmake

VC6_LIBTMPL = projects/Windows/VC6/lib/libcurl.tmpl
VC6_LIBDSP = projects/Windows/VC6/lib/libcurl.dsp
VC6_LIBDSP_DEPS = $(VC6_LIBTMPL) Makefile.am lib/Makefile.inc

VC7_LIBTMPL = projects/Windows/VC7/lib/libcurl.tmpl
VC7_LIBVCPROJ = projects/Windows/VC7/lib/libcurl.vcproj
VC7_LIBVCPROJ_DEPS = $(VC7_LIBTMPL) Makefile.am lib/Makefile.inc

VC71_LIBTMPL = projects/Windows/VC7.1/lib/libcurl.tmpl
VC71_LIBVCPROJ = projects/Windows/VC7.1/lib/libcurl.vcproj
VC71_LIBVCPROJ_DEPS = $(VC71_LIBTMPL) Makefile.am lib/Makefile.inc

VC8_LIBTMPL = projects/Windows/VC8/lib/libcurl.tmpl
VC8_LIBVCPROJ = projects/Windows/VC8/lib/libcurl.vcproj
VC8_LIBVCPROJ_DEPS = $(VC8_LIBTMPL) Makefile.am lib/Makefile.inc

VC9_LIBTMPL = projects/Windows/VC9/lib/libcurl.tmpl
VC9_LIBVCPROJ = projects/Windows/VC9/lib/libcurl.vcproj
VC9_LIBVCPROJ_DEPS = $(VC9_LIBTMPL) Makefile.am lib/Makefile.inc

VC10_LIBTMPL = projects/Windows/VC10/lib/libcurl.tmpl
VC10_LIBVCXPROJ = projects/Windows/VC10/lib/libcurl.vcxproj
VC10_LIBVCXPROJ_DEPS = $(VC10_LIBTMPL) Makefile.am lib/Makefile.inc

VC11_LIBTMPL = projects/Windows/VC11/lib/libcurl.tmpl
VC11_LIBVCXPROJ = projects/Windows/VC11/lib/libcurl.vcxproj
VC11_LIBVCXPROJ_DEPS = $(VC11_LIBTMPL) Makefile.am lib/Makefile.inc

VC12_LIBTMPL = projects/Windows/VC12/lib/libcurl.tmpl
VC12_LIBVCXPROJ = projects/Windows/VC12/lib/libcurl.vcxproj
VC12_LIBVCXPROJ_DEPS = $(VC12_LIBTMPL) Makefile.am lib/Makefile.inc

VC_DIST = projects/README	\
 projects/build-openssl.bat	\
 projects/Windows/VC6/curl.dsw	\
 projects/Windows/VC6/lib/libcurl.dsw $(VC6_LIBDSP)	\
 projects/Windows/VC6/src/curlsrc.dsw projects/Windows/VC6/src/curlsrc.tmpl	\
 projects/Windows/VC7/curl.sln	\
 projects/Windows/VC7/lib/libcurl.sln $(VC7_LIBVCPROJ)	\
 projects/Windows/VC7/src/curlsrc.sln projects/Windows/VC7/src/curlsrc.tmpl	\
 projects/Windows/VC7.1/curl.sln	\
 projects/Windows/VC7.1/lib/libcurl.sln $(VC71_LIBVCPROJ)	\
 projects/Windows/VC7.1/src/curlsrc.sln projects/Windows/VC7.1/src/curlsrc.tmpl	\
 projects/Windows/VC8/curl.sln	\
 projects/Windows/VC8/lib/libcurl.sln $(VC8_LIBVCPROJ)	\
 projects/Windows/VC8/src/curlsrc.sln projects/Windows/VC8/src/curlsrc.tmpl	\
 projects/Windows/VC9/curl.sln	\
 projects/Windows/VC9/lib/libcurl.sln $(VC9_LIBVCPROJ)	\
 projects/Windows/VC9/src/curlsrc.sln projects/Windows/VC9/src/curlsrc.tmpl	\
 projects/Windows/VC10/curl.sln	\
 projects/Windows/VC10/lib/libcurl.sln $(VC10_LIBVCXPROJ)	\
 projects/Windows/VC10/src/curlsrc.sln projects/Windows/VC10/src/curlsrc.tmpl	\
 projects/Windows/VC11/curl.sln	\
 projects/Windows/VC11/lib/libcurl.sln $(VC11_LIBVCXPROJ)	\
 projects/Windows/VC11/src/curlsrc.sln projects/Windows/VC11/src/curlsrc.tmpl	\
 projects/Windows/VC12/curl.sln	\
 projects/Windows/VC12/lib/libcurl.sln $(VC12_LIBVCXPROJ)	\
 projects/Windows/VC12/src/curlsrc.sln projects/Windows/VC12/src/curlsrc.tmpl

WINBUILD_DIST = winbuild/BUILD.WINDOWS.txt winbuild/gen_resp_file.bat	\
 winbuild/MakefileBuild.vc winbuild/Makefile.vc				\
 winbuild/Makefile.msvc.names

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in	\
 RELEASE-NOTES buildconf libcurl.pc.in MacOSX-Framework	\
 $(CMAKE_DIST) $(VC_DIST) $(WINBUILD_DIST) lib/libcurl.vers.in

CLEANFILES = $(VC6_LIBDSP) $(VC7_LIBVCPROJ) $(VC71_LIBVCPROJ) $(VC8_LIBVCPROJ)	\
 $(VC9_LIBVCPROJ) $(VC10_LIBVCXPROJ) $(VC11_LIBVCXPROJ) $(VC12_LIBVCXPROJ)

bin_SCRIPTS = curl-config

SUBDIRS = lib src include
DIST_SUBDIRS = $(SUBDIRS) tests packages docs

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurl.pc

# List of libcurl source files required to generate VC IDE dsp and prj files
include lib/Makefile.inc

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

.PHONY: vc-ide

vc-ide: $(VC6_LIBDSP_DEPS) $(VC7_LIBVCPROJ_DEPS) $(VC71_LIBVCPROJ_DEPS)	\
 $(VC8_LIBVCPROJ_DEPS) $(VC9_LIBVCPROJ_DEPS) $(VC10_LIBVCXPROJ_DEPS)	\
 $(VC11_LIBVCXPROJ_DEPS) $(VC12_LIBVCXPROJ_DEPS)
	@(win32_lib_srcs='$(LIB_CSOURCES)'; \
	win32_lib_hdrs='$(LIB_HHEADERS) config-win32.h'; \
	win32_lib_rc='$(LIB_RC)'; \
	win32_lib_vtls_srcs='$(LIB_VTLS_CSOURCES)'; \
	win32_lib_vtls_hdrs='$(LIB_VTLS_HHEADERS)'; \
	\
	sorted_lib_srcs=`for file in $$win32_lib_srcs; do echo $$file; done | sort`; \
	sorted_lib_hdrs=`for file in $$win32_lib_hdrs; do echo $$file; done | sort`; \
	sorted_lib_vtls_srcs=`for file in $$win32_lib_vtls_srcs; do echo $$file; done | sort`; \
	sorted_lib_vtls_hdrs=`for file in $$win32_lib_vtls_hdrs; do echo $$file; done | sort`; \
	\
	awk_code='\
function gen_element(type, dir, file)\
{\
  sub(/vtls\//, "", file);\
\
  spaces="    ";\
  if(dir == "lib\\vtls")\
    tabs="				";\
  else\
    tabs="			";\
\
  if(type == "dsp") {\
    printf("# Begin Source File\r\n");\
    printf("\r\n");\
    printf("SOURCE=..\\..\\..\\..\\%s\\%s\r\n", dir, file);\
    printf("# End Source File\r\n");\
  }\
  else if(type == "vcproj1") {\
    printf("%s<File\r\n", tabs);\
    printf("%s	RelativePath=\"..\\..\\..\\..\\%s\\%s\">\r\n",\
           tabs, dir, file);\
    printf("%s</File>\r\n", tabs);\
  }\
  else if(type == "vcproj2") {\
    printf("%s<File\r\n", tabs);\
    printf("%s	RelativePath=\"..\\..\\..\\..\\%s\\%s\"\r\n",\
           tabs, dir, file);\
    printf("%s>\r\n", tabs);\
    printf("%s</File>\r\n", tabs);\
  }\
  else if(type == "vcxproj") {\
    i = index(file, ".");\
    ext = substr(file, i == 0 ? 0 : i + 1);\
\
    if(ext == "c")\
      printf("%s<ClCompile Include=\"..\\..\\..\\..\\%s\\%s\" />\r\n",\
             spaces, dir, file);\
    else if(ext == "h")\
      printf("%s<ClInclude Include=\"..\\..\\..\\..\\%s\\%s\" />\r\n",\
             spaces, dir, file);\
    else if(ext == "rc")\
      printf("%s<ResourceCompile Include=\"..\\..\\..\\..\\%s\\%s\" >\r\n",\
      spaces, dir, file);\
  }\
}\
\
{\
\
  if($$0 == "CURL_LIB_C_FILES") {\
    split(lib_srcs, arr);\
    for(val in arr) gen_element(proj_type, "lib", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_H_FILES") {\
    split(lib_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "lib", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_RC_FILES") {\
    split(lib_rc, arr);\
    for(val in arr) gen_element(proj_type, "lib", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VTLS_C_FILES") {\
    split(lib_vtls_srcs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vtls", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VTLS_H_FILES") {\
    split(lib_vtls_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vtls", arr[val]);\
  }\
  else\
    printf("%s\r\n", $$0);\
}';\
	\
	echo "generating '$(VC6_LIBDSP)'"; \
	awk -v proj_type=dsp \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC6_LIBTMPL) > $(VC6_LIBDSP) || { exit 1; }; \
	\
	echo "generating '$(VC7_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj1 \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC7_LIBTMPL) > $(VC7_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC71_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj1 \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC71_LIBTMPL) > $(VC71_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC8_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj2 \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC8_LIBTMPL) > $(VC8_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC9_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj2 \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC9_LIBTMPL) > $(VC9_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC10_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC10_LIBTMPL) > $(VC10_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC11_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC11_LIBTMPL) > $(VC11_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC12_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC12_LIBTMPL) > $(VC12_LIBVCXPROJ) || { exit 1; };)
