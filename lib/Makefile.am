#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# $Id$
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

DSP = curllib.dsp

EXTRA_DIST = Makefile.b32 Makefile.m32	\
  Makefile.vc6 Makefile.riscos libcurl.def $(DSP) curllib.dsw		\
  config-vms.h config-win32.h config-riscos.h config-mac.h config.h.in	\
  ca-bundle.crt README.encoding README.memoryleak README.ares		\
  README.curlx makefile.dj config.dj libcurl.framework.make		\
  libcurl.plist libcurl.rc config-amigaos.h amigaos.c amigaos.h		\
  makefile.amiga Makefile.netware nwlib.c libcurl.imp	\
  msvcproj.head msvcproj.foot

CLEANFILES = $(DSP)

lib_LTLIBRARIES = libcurl.la

# we use srcdir/include for the static global include files
# we use builddir/lib for the generated lib/config.h file to get found
# we use srcdir/lib for the lib-private header files
INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/lib -I$(top_srcdir)/lib

VERSION=-version-info 3:0:0

# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# If either revision or age are omitted, they default to 0. Also note that age
# must be less than or equal to the current interface number.
#
# Here are a set of rules to help you update your library version information: 
#
# 1.Start with version information of 0:0:0 for each libtool library.
#
# 2.Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
#
# 3.If the library source code has changed at all since the last update, then
# increment revision (c:r+1:a)
#
# 4.If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0. (c+1:r=0:a)
#
# 5.If any interfaces have been added since the last public release, then
# increment age. (c:r:a+1)
#
# 6.If any interfaces have been removed since the last public release, then
# set age to 0. (c:r:a=0)
#

if NO_UNDEFINED
# The -no-undefined flag is CRUCIAL for this to build fine on Cygwin.
UNDEF = -no-undefined
endif

if MIMPURE
# This is for gcc on Solaris (8+ ?) to avoid "relocations remain against
# allocatable but non-writable sections" problems.
MIMPURE = -mimpure-text
endif

libcurl_la_LDFLAGS = $(UNDEF) $(VERSION) $(MIMPURE)

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcurl_la_SOURCES = $(CSOURCES) $(HHEADERS)

WIN32SOURCES = $(CSOURCES) libcurl.def
WIN32HEADERS = $(HHEADERS) config-win32.h

BUILT_SOURCES = $(top_builddir)/lib/ca-bundle.h

$(top_builddir)/lib/ca-bundle.h: Makefile.in Makefile
	@if test -f $@; then \
	  chmod 0644 $@; \
	fi
	echo "/* This file is generated automatically */" > $@
if CABUNDLE
	echo '#define CURL_CA_BUNDLE @CURL_CA_BUNDLE@' >> $@
else
	echo '#undef CURL_CA_BUNDLE /* unknown */' >> $@
endif

install-data-hook:
	@if test -n "@CURL_CA_BUNDLE@"; then \
	  $(mkinstalldirs) `dirname $(DESTDIR)@CURL_CA_BUNDLE@`; \
	  @INSTALL_DATA@ $(srcdir)/ca-bundle.crt $(DESTDIR)@CURL_CA_BUNDLE@; \
        fi

# this hook is mainly for non-unix systems to build even if configure
# isn't run
dist-hook:
	chmod 0644 $(distdir)/ca-bundle.h
	echo "/* ca bundle path set in here*/" > $(distdir)/ca-bundle.h

DSPOUT = | awk '{printf("%s\r\n", $$0)}' >> $(DSP)

$(DSP): msvcproj.head msvcproj.foot Makefile.am
	echo "creating $(DSP)"
	@(cp msvcproj.head $(DSP); \
	echo "# Begin Group \"Source Files\"" $(DSPOUT); \
	for file in $(WIN32SOURCES); do \
	echo "# Begin Source File" $(DSPOUT); \
	echo "" $(DSPOUT); \
	echo "SOURCE=.\\"$$file $(DSPOUT); \
	echo "# End Source File" $(DSPOUT); \
	done; \
	echo "# End Group" $(DSPOUT); \
	echo "# Begin Group \"Header Files\"" $(DSPOUT); \
	for file in $(WIN32HEADERS); do \
	echo "# Begin Source File" $(DSPOUT); \
	echo "" $(DSPOUT); \
	echo "SOURCE=.\\"$$file $(DSPOUT); \
	echo "# End Source File" $(DSPOUT); \
	done; \
	echo "# End Group" $(DSPOUT); \
	cat msvcproj.foot $(DSPOUT) )
