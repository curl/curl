#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 CMake/FindLibSSH2.cmake                        \
 CMake/FindMbedTLS.cmake                        \
 CMake/FindNGHTTP2.cmake                        \
 CMake/FindNGHTTP3.cmake                        \
 CMake/FindNGTCP2.cmake                         \
 CMake/FindNSS.cmake                            \
 CMake/FindQUICHE.cmake                         \
 CMake/FindWolfSSL.cmake                        \
 CMake/FindZstd.cmake                           \
 CMake/Macros.cmake                             \
 CMake/OtherTests.cmake                         \
 CMake/Platforms/WindowsCache.cmake             \
 CMake/Utilities.cmake                          \
 CMakeLists.txt

VC6_LIBTMPL = projects/Windows/VC6/lib/libcurl.tmpl
VC6_LIBDSP = projects/Windows/VC6/lib/libcurl.dsp.dist
VC6_LIBDSP_DEPS = $(VC6_LIBTMPL) Makefile.am lib/Makefile.inc
VC6_SRCTMPL = projects/Windows/VC6/src/curl.tmpl
VC6_SRCDSP = projects/Windows/VC6/src/curl.dsp.dist
VC6_SRCDSP_DEPS = $(VC6_SRCTMPL) Makefile.am src/Makefile.inc

VC7_LIBTMPL = projects/Windows/VC7/lib/libcurl.tmpl
VC7_LIBVCPROJ = projects/Windows/VC7/lib/libcurl.vcproj.dist
VC7_LIBVCPROJ_DEPS = $(VC7_LIBTMPL) Makefile.am lib/Makefile.inc
VC7_SRCTMPL = projects/Windows/VC7/src/curl.tmpl
VC7_SRCVCPROJ = projects/Windows/VC7/src/curl.vcproj.dist
VC7_SRCVCPROJ_DEPS = $(VC7_SRCTMPL) Makefile.am src/Makefile.inc

VC71_LIBTMPL = projects/Windows/VC7.1/lib/libcurl.tmpl
VC71_LIBVCPROJ = projects/Windows/VC7.1/lib/libcurl.vcproj.dist
VC71_LIBVCPROJ_DEPS = $(VC71_LIBTMPL) Makefile.am lib/Makefile.inc
VC71_SRCTMPL = projects/Windows/VC7.1/src/curl.tmpl
VC71_SRCVCPROJ = projects/Windows/VC7.1/src/curl.vcproj.dist
VC71_SRCVCPROJ_DEPS = $(VC71_SRCTMPL) Makefile.am src/Makefile.inc

VC8_LIBTMPL = projects/Windows/VC8/lib/libcurl.tmpl
VC8_LIBVCPROJ = projects/Windows/VC8/lib/libcurl.vcproj.dist
VC8_LIBVCPROJ_DEPS = $(VC8_LIBTMPL) Makefile.am lib/Makefile.inc
VC8_SRCTMPL = projects/Windows/VC8/src/curl.tmpl
VC8_SRCVCPROJ = projects/Windows/VC8/src/curl.vcproj.dist
VC8_SRCVCPROJ_DEPS = $(VC8_SRCTMPL) Makefile.am src/Makefile.inc

VC9_LIBTMPL = projects/Windows/VC9/lib/libcurl.tmpl
VC9_LIBVCPROJ = projects/Windows/VC9/lib/libcurl.vcproj.dist
VC9_LIBVCPROJ_DEPS = $(VC9_LIBTMPL) Makefile.am lib/Makefile.inc
VC9_SRCTMPL = projects/Windows/VC9/src/curl.tmpl
VC9_SRCVCPROJ = projects/Windows/VC9/src/curl.vcproj.dist
VC9_SRCVCPROJ_DEPS = $(VC9_SRCTMPL) Makefile.am src/Makefile.inc

VC10_LIBTMPL = projects/Windows/VC10/lib/libcurl.tmpl
VC10_LIBVCXPROJ = projects/Windows/VC10/lib/libcurl.vcxproj.dist
VC10_LIBVCXPROJ_DEPS = $(VC10_LIBTMPL) Makefile.am lib/Makefile.inc
VC10_SRCTMPL = projects/Windows/VC10/src/curl.tmpl
VC10_SRCVCXPROJ = projects/Windows/VC10/src/curl.vcxproj.dist
VC10_SRCVCXPROJ_DEPS = $(VC10_SRCTMPL) Makefile.am src/Makefile.inc

VC11_LIBTMPL = projects/Windows/VC11/lib/libcurl.tmpl
VC11_LIBVCXPROJ = projects/Windows/VC11/lib/libcurl.vcxproj.dist
VC11_LIBVCXPROJ_DEPS = $(VC11_LIBTMPL) Makefile.am lib/Makefile.inc
VC11_SRCTMPL = projects/Windows/VC11/src/curl.tmpl
VC11_SRCVCXPROJ = projects/Windows/VC11/src/curl.vcxproj.dist
VC11_SRCVCXPROJ_DEPS = $(VC11_SRCTMPL) Makefile.am src/Makefile.inc

VC12_LIBTMPL = projects/Windows/VC12/lib/libcurl.tmpl
VC12_LIBVCXPROJ = projects/Windows/VC12/lib/libcurl.vcxproj.dist
VC12_LIBVCXPROJ_DEPS = $(VC12_LIBTMPL) Makefile.am lib/Makefile.inc
VC12_SRCTMPL = projects/Windows/VC12/src/curl.tmpl
VC12_SRCVCXPROJ = projects/Windows/VC12/src/curl.vcxproj.dist
VC12_SRCVCXPROJ_DEPS = $(VC12_SRCTMPL) Makefile.am src/Makefile.inc

VC14_LIBTMPL = projects/Windows/VC14/lib/libcurl.tmpl
VC14_LIBVCXPROJ = projects/Windows/VC14/lib/libcurl.vcxproj.dist
VC14_LIBVCXPROJ_DEPS = $(VC14_LIBTMPL) Makefile.am lib/Makefile.inc
VC14_SRCTMPL = projects/Windows/VC14/src/curl.tmpl
VC14_SRCVCXPROJ = projects/Windows/VC14/src/curl.vcxproj.dist
VC14_SRCVCXPROJ_DEPS = $(VC14_SRCTMPL) Makefile.am src/Makefile.inc

VC15_LIBTMPL = projects/Windows/VC15/lib/libcurl.tmpl
VC15_LIBVCXPROJ = projects/Windows/VC15/lib/libcurl.vcxproj.dist
VC15_LIBVCXPROJ_DEPS = $(VC15_LIBTMPL) Makefile.am lib/Makefile.inc
VC15_SRCTMPL = projects/Windows/VC15/src/curl.tmpl
VC15_SRCVCXPROJ = projects/Windows/VC15/src/curl.vcxproj.dist
VC15_SRCVCXPROJ_DEPS = $(VC15_SRCTMPL) Makefile.am src/Makefile.inc

VC_DIST = projects/README                           \
 projects/build-openssl.bat                         \
 projects/build-wolfssl.bat                         \
 projects/checksrc.bat                              \
 projects/Windows/VC6/curl-all.dsw                  \
 projects/Windows/VC6/lib/libcurl.dsw               \
 projects/Windows/VC6/src/curl.dsw                  \
 projects/Windows/VC7/curl-all.sln                  \
 projects/Windows/VC7/lib/libcurl.sln               \
 projects/Windows/VC7/src/curl.sln                  \
 projects/Windows/VC7.1/curl-all.sln                \
 projects/Windows/VC7.1/lib/libcurl.sln             \
 projects/Windows/VC7.1/src/curl.sln                \
 projects/Windows/VC8/curl-all.sln                  \
 projects/Windows/VC8/lib/libcurl.sln               \
 projects/Windows/VC8/src/curl.sln                  \
 projects/Windows/VC9/curl-all.sln                  \
 projects/Windows/VC9/lib/libcurl.sln               \
 projects/Windows/VC9/src/curl.sln                  \
 projects/Windows/VC10/curl-all.sln                 \
 projects/Windows/VC10/lib/libcurl.sln              \
 projects/Windows/VC10/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC10/src/curl.sln                 \
 projects/Windows/VC10/src/curl.vcxproj.filters     \
 projects/Windows/VC11/curl-all.sln                 \
 projects/Windows/VC11/lib/libcurl.sln              \
 projects/Windows/VC11/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC11/src/curl.sln                 \
 projects/Windows/VC11/src/curl.vcxproj.filters     \
 projects/Windows/VC12/curl-all.sln                 \
 projects/Windows/VC12/lib/libcurl.sln              \
 projects/Windows/VC12/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC12/src/curl.sln                 \
 projects/Windows/VC12/src/curl.vcxproj.filters     \
 projects/Windows/VC14/curl-all.sln                 \
 projects/Windows/VC14/lib/libcurl.sln              \
 projects/Windows/VC14/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC14/src/curl.sln                 \
 projects/Windows/VC14/src/curl.vcxproj.filters     \
 projects/Windows/VC15/curl-all.sln                 \
 projects/Windows/VC15/lib/libcurl.sln              \
 projects/Windows/VC15/lib/libcurl.vcxproj.filters  \
 projects/Windows/VC15/src/curl.sln                 \
 projects/Windows/VC15/src/curl.vcxproj.filters     \
 projects/generate.bat                              \
 projects/wolfssl_options.h                         \
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

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in \
 RELEASE-NOTES buildconf libcurl.pc.in MacOSX-Framework \
 scripts/updatemanpages.pl $(CMAKE_DIST) \
 $(VC_DIST) $(WINBUILD_DIST) $(PLAN9_DIST) \
 lib/libcurl.vers.in buildconf.bat scripts/coverage.sh scripts/completion.pl

CLEANFILES = $(VC6_LIBDSP) $(VC6_SRCDSP) $(VC7_LIBVCPROJ) $(VC7_SRCVCPROJ) \
 $(VC71_LIBVCPROJ) $(VC71_SRCVCPROJ) $(VC8_LIBVCPROJ) $(VC8_SRCVCPROJ) \
 $(VC9_LIBVCPROJ) $(VC9_SRCVCPROJ) $(VC10_LIBVCXPROJ) $(VC10_SRCVCXPROJ) \
 $(VC11_LIBVCXPROJ) $(VC11_SRCVCXPROJ) $(VC12_LIBVCXPROJ) $(VC12_SRCVCXPROJ) \
 $(VC14_LIBVCXPROJ) $(VC14_SRCVCXPROJ) $(VC15_LIBVCXPROJ) $(VC15_SRCVCXPROJ)

bin_SCRIPTS = curl-config

SUBDIRS = lib src
DIST_SUBDIRS = $(SUBDIRS) tests packages scripts include docs

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

ca-bundle: lib/mk-ca-bundle.pl
	@echo "generating a fresh ca-bundle.crt"
	@perl $< -b -l -u lib/ca-bundle.crt

ca-firefox: lib/firefox-db2pem.sh
	@echo "generating a fresh ca-bundle.crt"
	./lib/firefox-db2pem.sh lib/ca-bundle.crt

checksrc:
	(cd lib && $(MAKE) checksrc)
	(cd src && $(MAKE) checksrc)
	(cd tests && $(MAKE) checksrc)
	(cd include/curl && $(MAKE) checksrc)
	(cd docs/examples && $(MAKE) checksrc)
	(cd packages && $(MAKE) checksrc)

.PHONY: vc-ide

vc-ide: $(VC6_LIBDSP_DEPS) $(VC6_SRCDSP_DEPS) $(VC7_LIBVCPROJ_DEPS) \
 $(VC7_SRCVCPROJ_DEPS) $(VC71_LIBVCPROJ_DEPS) $(VC71_SRCVCPROJ_DEPS) \
 $(VC8_LIBVCPROJ_DEPS) $(VC8_SRCVCPROJ_DEPS) $(VC9_LIBVCPROJ_DEPS) \
 $(VC9_SRCVCPROJ_DEPS) $(VC10_LIBVCXPROJ_DEPS) $(VC10_SRCVCXPROJ_DEPS) \
 $(VC11_LIBVCXPROJ_DEPS) $(VC11_SRCVCXPROJ_DEPS) $(VC12_LIBVCXPROJ_DEPS) \
 $(VC12_SRCVCXPROJ_DEPS) $(VC14_LIBVCXPROJ_DEPS) $(VC14_SRCVCXPROJ_DEPS) \
 $(VC15_LIBVCXPROJ_DEPS) $(VC15_SRCVCXPROJ_DEPS)
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
	echo "generating '$(VC6_LIBDSP)'"; \
	awk -v proj_type=dsp \
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
		"$$awk_code" $(srcdir)/$(VC6_LIBTMPL) > $(VC6_LIBDSP) || { exit 1; }; \
	\
	echo "generating '$(VC6_SRCDSP)'"; \
	awk -v proj_type=dsp \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC6_SRCTMPL) > $(VC6_SRCDSP) || { exit 1; }; \
	\
	echo "generating '$(VC7_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj1 \
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
		"$$awk_code" $(srcdir)/$(VC7_LIBTMPL) > $(VC7_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC7_SRCVCPROJ)'"; \
	awk -v proj_type=vcproj1 \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC7_SRCTMPL) > $(VC7_SRCVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC71_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj1 \
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
		"$$awk_code" $(srcdir)/$(VC71_LIBTMPL) > $(VC71_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC71_SRCVCPROJ)'"; \
	awk -v proj_type=vcproj1 \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC71_SRCTMPL) > $(VC71_SRCVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC8_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj2 \
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
		"$$awk_code" $(srcdir)/$(VC8_LIBTMPL) > $(VC8_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC8_SRCVCPROJ)'"; \
	awk -v proj_type=vcproj2 \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC8_SRCTMPL) > $(VC8_SRCVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC9_LIBVCPROJ)'"; \
	awk -v proj_type=vcproj2 \
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
		"$$awk_code" $(srcdir)/$(VC9_LIBTMPL) > $(VC9_LIBVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC9_SRCVCPROJ)'"; \
	awk -v proj_type=vcproj2 \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC9_SRCTMPL) > $(VC9_SRCVCPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC10_LIBVCXPROJ)'"; \
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
		"$$awk_code" $(srcdir)/$(VC10_LIBTMPL) > $(VC10_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC10_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC10_SRCTMPL) > $(VC10_SRCVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC11_LIBVCXPROJ)'"; \
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
		"$$awk_code" $(srcdir)/$(VC11_LIBTMPL) > $(VC11_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC11_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC11_SRCTMPL) > $(VC11_SRCVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC12_LIBVCXPROJ)'"; \
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
		"$$awk_code" $(srcdir)/$(VC12_LIBTMPL) > $(VC12_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC12_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC12_SRCTMPL) > $(VC12_SRCVCXPROJ) || { exit 1; }; \
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
	echo "generating '$(VC15_LIBVCXPROJ)'"; \
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
		"$$awk_code" $(srcdir)/$(VC15_LIBTMPL) > $(VC15_LIBVCXPROJ) || { exit 1; }; \
	\
	echo "generating '$(VC15_SRCVCXPROJ)'"; \
	awk -v proj_type=vcxproj \
		-v src_srcs="$$sorted_src_srcs" \
		-v src_hdrs="$$sorted_src_hdrs" \
		-v src_rc="$$win32_src_rc" \
		-v src_x_srcs="$$sorted_src_x_srcs" \
		-v src_x_hdrs="$$sorted_src_x_hdrs" \
		"$$awk_code" $(srcdir)/$(VC15_SRCTMPL) > $(VC15_SRCVCXPROJ) || { exit 1; };)

tidy:
	(cd src && $(MAKE) tidy)
	(cd lib && $(MAKE) tidy)
