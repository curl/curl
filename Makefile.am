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

VC14_LIBTMPL = projects/Windows/VC14/lib/libcurl.tmpl
VC14_LIBVCXPROJ = projects/Windows/VC14/lib/libcurl.vcxproj.dist
VC14_LIBVCXPROJ_DEPS = $(VC14_LIBTMPL) Makefile.am lib/Makefile.inc
VC14_SRCTMPL = projects/Windows/VC14/src/curl.tmpl
VC14_SRCVCXPROJ = projects/Windows/VC14/src/curl.vcxproj.dist
VC14_SRCVCXPROJ_DEPS = $(VC14_SRCTMPL) Makefile.am src/Makefile.inc

VC14_10_LIBTMPL = projects/Windows/VC14.10/lib/libcurl.tmpl
VC14_10_LIBVCXPROJ = projects/Windows/VC14.10/lib/libcurl.vcxproj.dist
VC14_10_LIBVCXPROJ_DEPS = $(VC14_10_LIBTMPL) Makefile.am lib/Makefile.inc
VC14_10_SRCTMPL = projects/Windows/VC14.10/src/curl.tmpl
VC14_10_SRCVCXPROJ = projects/Windows/VC14.10/src/curl.vcxproj.dist
VC14_10_SRCVCXPROJ_DEPS = $(VC14_10_SRCTMPL) Makefile.am src/Makefile.inc

VC14_20_LIBTMPL = projects/Windows/VC14.20/lib/libcurl.tmpl
VC14_20_LIBVCXPROJ = projects/Windows/VC14.20/lib/libcurl.vcxproj.dist
VC14_20_LIBVCXPROJ_DEPS = $(VC14_20_LIBTMPL) Makefile.am lib/Makefile.inc
VC14_20_SRCTMPL = projects/Windows/VC14.20/src/curl.tmpl
VC14_20_SRCVCXPROJ = projects/Windows/VC14.20/src/curl.vcxproj.dist
VC14_20_SRCVCXPROJ_DEPS = $(VC14_20_SRCTMPL) Makefile.am src/Makefile.inc

VC14_30_LIBTMPL = projects/Windows/VC14.30/lib/libcurl.tmpl
VC14_30_LIBVCXPROJ = projects/Windows/VC14.30/lib/libcurl.vcxproj.dist
VC14_30_LIBVCXPROJ_DEPS = $(VC14_30_LIBTMPL) Makefile.am lib/Makefile.inc
VC14_30_SRCTMPL = projects/Windows/VC14.30/src/curl.tmpl
VC14_30_SRCVCXPROJ = projects/Windows/VC14.30/src/curl.vcxproj.dist
VC14_30_SRCVCXPROJ_DEPS = $(VC14_30_SRCTMPL) Makefile.am src/Makefile.inc

VC_DIST = projects/README.md                           \
 projects/build-openssl.bat                            \
 projects/build-wolfssl.bat                            \
 projects/checksrc.bat                                 \
 projects/Windows/VC14/curl-all.sln                    \
 projects/Windows/VC14/lib/libcurl.sln                 \
 projects/Windows/VC14/lib/libcurl.vcxproj.filters     \
 projects/Windows/VC14/src/curl.sln                    \
 projects/Windows/VC14/src/curl.vcxproj.filters        \
 projects/Windows/VC14.10/curl-all.sln                 \
 projects/Windows/VC14.10/lib/libcurl.sln              \
 projects/Windows/VC14.10/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC14.10/src/curl.sln                 \
 projects/Windows/VC14.10/src/curl.vcxproj.filters     \
 projects/Windows/VC14.20/curl-all.sln                 \
 projects/Windows/VC14.20/lib/libcurl.sln              \
 projects/Windows/VC14.20/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC14.20/src/curl.sln                 \
 projects/Windows/VC14.20/src/curl.vcxproj.filters     \
 projects/Windows/VC14.30/curl-all.sln                 \
 projects/Windows/VC14.30/lib/libcurl.sln              \
 projects/Windows/VC14.30/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC14.30/src/curl.sln                 \
 projects/Windows/VC14.30/src/curl.vcxproj.filters     \
 projects/generate.bat                                 \
 projects/wolfssl_options.h                            \
 projects/wolfssl_override.props

WINBUILD_DIST = winbuild/README.md winbuild/gen_resp_file.bat \
 winbuild/MakefileBuild.vc winbuild/Makefile.vc

PLAN9_DIST = plan9/include/mkfile \
 plan9/include/mkfile             \
 plan9/mkfile.proto               \
 plan9/mkfile                     \
 plan9/README                     \
 plan9/lib/mkfile.inc             \
 plan9/lib/mkfile                 \
 plan9/src/mkfile.inc             \
 plan9/src/mkfile

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in            \
 RELEASE-NOTES buildconf libcurl.pc.in MacOSX-Framework $(CMAKE_DIST)        \
 $(VC_DIST) $(WINBUILD_DIST) $(PLAN9_DIST) lib/libcurl.vers.in buildconf.bat \
 libcurl.def

CLEANFILES = $(VC14_LIBVCXPROJ) \
 $(VC14_SRCVCXPROJ) $(VC14_10_LIBVCXPROJ) $(VC14_10_SRCVCXPROJ)              \
 $(VC14_30_LIBVCXPROJ) $(VC14_30_SRCVCXPROJ)

bin_SCRIPTS = curl-config

SUBDIRS = lib src
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

html:
	cd docs && $(MAKE) html

pdf:
	cd docs && $(MAKE) pdf

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
install-data-hook:
	(cd include && $(MAKE) install)
	(cd docs && $(MAKE) install)
	(cd docs/libcurl && $(MAKE) install)

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

.PHONY: vc-ide

vc-ide: $(VC14_LIBVCXPROJ_DEPS) $(VC14_SRCVCXPROJ_DEPS) \
 $(VC14_10_LIBVCXPROJ_DEPS) $(VC14_10_SRCVCXPROJ_DEPS)  \
 $(VC14_20_LIBVCXPROJ_DEPS) $(VC14_20_SRCVCXPROJ_DEPS)  \
 $(VC14_30_LIBVCXPROJ_DEPS) $(VC14_30_SRCVCXPROJ_DEPS)
	@(win32_lib_srcs='$(LIB_CFILES)'; \
	win32_lib_hdrs='$(LIB_HFILES) config-win32.h'; \
	win32_lib_rc='$(LIB_RCFILES)'; \
	win32_lib_vauth_srcs='$(LIB_VAUTH_CFILES)'; \
	win32_lib_vauth_hdrs='$(LIB_VAUTH_HFILES)'; \
	win32_lib_vquic_srcs='$(LIB_VQUIC_CFILES)'; \
	win32_lib_vquic_hdrs='$(LIB_VQUIC_HFILES)'; \
	win32_lib_vssh_srcs='$(LIB_VSSH_CFILES)'; \
	win32_lib_vssh_hdrs='$(LIB_VSSH_HFILES)'; \
	win32_lib_vtls_srcs='$(LIB_VTLS_CFILES)'; \
	win32_lib_vtls_hdrs='$(LIB_VTLS_HFILES)'; \
	win32_src_srcs='$(CURL_CFILES)'; \
	win32_src_hdrs='$(CURL_HFILES)'; \
	win32_src_rc='$(CURL_RCFILES)'; \
	win32_src_x_srcs='$(CURLX_CFILES)'; \
	win32_src_x_hdrs='$(CURLX_HFILES) ../lib/config-win32.h'; \
	\
	sorted_lib_srcs=`for file in $$win32_lib_srcs; do echo $$file; done | sort`; \
	sorted_lib_hdrs=`for file in $$win32_lib_hdrs; do echo $$file; done | sort`; \
	sorted_lib_vauth_srcs=`for file in $$win32_lib_vauth_srcs; do echo $$file; done | sort`; \
	sorted_lib_vauth_hdrs=`for file in $$win32_lib_vauth_hdrs; do echo $$file; done | sort`; \
	sorted_lib_vquic_srcs=`for file in $$win32_lib_vquic_srcs; do echo $$file; done | sort`; \
	sorted_lib_vquic_hdrs=`for file in $$win32_lib_vquic_hdrs; do echo $$file; done | sort`; \
	sorted_lib_vssh_srcs=`for file in $$win32_lib_vssh_srcs; do echo $$file; done | sort`; \
	sorted_lib_vssh_hdrs=`for file in $$win32_lib_vssh_hdrs; do echo $$file; done | sort`; \
	sorted_lib_vtls_srcs=`for file in $$win32_lib_vtls_srcs; do echo $$file; done | sort`; \
	sorted_lib_vtls_hdrs=`for file in $$win32_lib_vtls_hdrs; do echo $$file; done | sort`; \
	sorted_src_srcs=`for file in $$win32_src_srcs; do echo $$file; done | sort`; \
	sorted_src_hdrs=`for file in $$win32_src_hdrs; do echo $$file; done | sort`; \
	sorted_src_x_srcs=`for file in $$win32_src_x_srcs; do echo $$file; done | sort`; \
	sorted_src_x_hdrs=`for file in $$win32_src_x_hdrs; do echo $$file; done | sort`; \
	\
	awk_code='\
function gen_element(type, dir, file)\
{\
  sub(/vauth\//, "", file);\
  sub(/vquic\//, "", file);\
  sub(/vssh\//, "", file);\
  sub(/vtls\//, "", file);\
\
  spaces="    ";\
  if(dir == "lib\\vauth" ||\
     dir == "lib\\vquic" ||\
     dir == "lib\\vssh"  ||\
     dir == "lib\\vtls")\
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
      printf("%s<ResourceCompile Include=\"..\\..\\..\\..\\%s\\%s\" />\r\n",\
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
  else if($$0 == "CURL_LIB_VAUTH_C_FILES") {\
    split(lib_vauth_srcs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vauth", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VAUTH_H_FILES") {\
    split(lib_vauth_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vauth", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VQUIC_C_FILES") {\
    split(lib_vquic_srcs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vquic", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VQUIC_H_FILES") {\
    split(lib_vquic_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vquic", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VSSH_C_FILES") {\
    split(lib_vssh_srcs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vssh", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VSSH_H_FILES") {\
    split(lib_vssh_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vssh", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VTLS_C_FILES") {\
    split(lib_vtls_srcs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vtls", arr[val]);\
  }\
  else if($$0 == "CURL_LIB_VTLS_H_FILES") {\
    split(lib_vtls_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "lib\\vtls", arr[val]);\
  }\
  else if($$0 == "CURL_SRC_C_FILES") {\
    split(src_srcs, arr);\
    for(val in arr) gen_element(proj_type, "src", arr[val]);\
  }\
  else if($$0 == "CURL_SRC_H_FILES") {\
    split(src_hdrs, arr);\
    for(val in arr) gen_element(proj_type, "src", arr[val]);\
  }\
  else if($$0 == "CURL_SRC_RC_FILES") {\
    split(src_rc, arr);\
    for(val in arr) gen_element(proj_type, "src", arr[val]);\
  }\
  else if($$0 == "CURL_SRC_X_C_FILES") {\
    split(src_x_srcs, arr);\
    for(val in arr) {\
      sub(/..\/lib\//, "", arr[val]);\
      gen_element(proj_type, "lib", arr[val]);\
    }\
  }\
  else if($$0 == "CURL_SRC_X_H_FILES") {\
    split(src_x_hdrs, arr);\
    for(val in arr) {\
      sub(/..\/lib\//, "", arr[val]);\
      gen_element(proj_type, "lib", arr[val]);\
    }\
  }\
  else\
    printf("%s\r\n", $$0);\
}';\
	\
	echo "generating '$(VC14_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vauth_srcs="$$sorted_lib_vauth_srcs" \
		-v lib_vauth_hdrs="$$sorted_lib_vauth_hdrs" \
		-v lib_vquic_srcs="$$sorted_lib_vquic_srcs" \
		-v lib_vquic_hdrs="$$sorted_lib_vquic_hdrs" \
		-v lib_vssh_srcs="$$sorted_lib_vssh_srcs" \
		-v lib_vssh_hdrs="$$sorted_lib_vssh_hdrs" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_LIBTMPL) > $(VC14_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC14_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_SRCTMPL) > $(VC14_SRCVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC14_10_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vauth_srcs="$$sorted_lib_vauth_srcs" \
		-v lib_vauth_hdrs="$$sorted_lib_vauth_hdrs" \
		-v lib_vquic_srcs="$$sorted_lib_vquic_srcs" \
		-v lib_vquic_hdrs="$$sorted_lib_vquic_hdrs" \
		-v lib_vssh_srcs="$$sorted_lib_vssh_srcs" \
		-v lib_vssh_hdrs="$$sorted_lib_vssh_hdrs" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_10_LIBTMPL) > $(VC14_10_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC14_10_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_10_SRCTMPL) > $(VC14_10_SRCVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC14_20_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vauth_srcs="$$sorted_lib_vauth_srcs" \
		-v lib_vauth_hdrs="$$sorted_lib_vauth_hdrs" \
		-v lib_vquic_srcs="$$sorted_lib_vquic_srcs" \
		-v lib_vquic_hdrs="$$sorted_lib_vquic_hdrs" \
		-v lib_vssh_srcs="$$sorted_lib_vssh_srcs" \
		-v lib_vssh_hdrs="$$sorted_lib_vssh_hdrs" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_20_LIBTMPL) > $(VC14_20_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC14_20_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_20_SRCTMPL) > $(VC14_20_SRCVCXPROJ) || { exit 1; };) \
	echo "generating '$(VC14_30_LIBVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v lib_srcs="$$sorted_lib_srcs" \
		-v lib_hdrs="$$sorted_lib_hdrs" \
		-v lib_rc="$$win32_lib_rc" \
		-v lib_vauth_srcs="$$sorted_lib_vauth_srcs" \
		-v lib_vauth_hdrs="$$sorted_lib_vauth_hdrs" \
		-v lib_vquic_srcs="$$sorted_lib_vquic_srcs" \
		-v lib_vquic_hdrs="$$sorted_lib_vquic_hdrs" \
		-v lib_vssh_srcs="$$sorted_lib_vssh_srcs" \
		-v lib_vssh_hdrs="$$sorted_lib_vssh_hdrs" \
		-v lib_vtls_srcs="$$sorted_lib_vtls_srcs" \
		-v lib_vtls_hdrs="$$sorted_lib_vtls_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_30_LIBTMPL) > $(VC14_30_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC14_30_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC14_30_SRCTMPL) > $(VC14_30_SRCVCXPROJ) || { exit 1; };)

tidy:
	(cd src && $(MAKE) tidy)
	(cd lib && $(MAKE) tidy)
