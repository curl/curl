#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
AUTOMAKE_OPTIONS = foreign nostdinc

# remove targets if the command fails
.DELETE_ON_ERROR:

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_builddir)/src is for curl's generated src/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files
# $(top_srcdir)/src is for curl's src/tool_setup.h and "curl-private" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_builddir)/src          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/src

bin_PROGRAMS = curl

SUBDIRS = ../docs

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif

include Makefile.inc

# CURL_FILES comes from Makefile.inc
curl_SOURCES = $(CURL_FILES)

# This might hold -Werror
CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

if USE_EXPLICIT_LIB_DEPS
curl_LDADD = $(top_builddir)/lib/libcurl.la @LIBCURL_LIBS@
else
curl_LDADD = $(top_builddir)/lib/libcurl.la @NSS_LIBS@ @SSL_LIBS@ @ZLIB_LIBS@ @CURL_NETWORK_AND_TIME_LIBS@
endif

# if unit tests are enabled, build a static library to link them with
if BUILD_UNITTESTS
noinst_LTLIBRARIES = libcurltool.la
libcurltool_la_CPPFLAGS = $(AM_CPPFLAGS) \
                          -DCURL_STATICLIB -DUNITTESTS
libcurltool_la_CFLAGS =
libcurltool_la_LDFLAGS = -static $(LINKFLAGS)
libcurltool_la_SOURCES = $(curl_SOURCES)
endif

CLEANFILES = tool_hugehelp.c
# Use the C locale to ensure that only ASCII characters appear in the
# embedded text.
NROFF=env LC_ALL=C @NROFF@ @MANOPT@ # figured out by the configure script

EXTRA_DIST = mkhelp.pl makefile.dj                                     \
 Makefile.m32 makefile.amiga curl.rc Makefile.inc CMakeLists.txt

# Use absolute directory to disable VPATH
MANPAGE=$(abs_top_builddir)/docs/curl.1
MKHELP=$(top_srcdir)/src/mkhelp.pl
HUGE=tool_hugehelp.c

HUGECMD = $(HUGEIT_$(V))
HUGEIT_0 = @echo "  HUGE    " $@;
HUGEIT_1 =
HUGEIT_ = $(HUGEIT_0)

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

if USE_MANUAL
# Here are the stuff to create a built-in manual

$(MANPAGE):
	cd $(top_builddir)/docs && $(MAKE)

if HAVE_LIBZ
# This generates the tool_hugehelp.c file in both uncompressed and
# compressed formats.
$(HUGE): $(MANPAGE) $(MKHELP)
	$(HUGECMD) (echo '#include "tool_setup.h"' > $(HUGE);   \
	echo '#ifndef HAVE_LIBZ' >> $(HUGE);                    \
	$(NROFF) $(MANPAGE) | $(PERL) $(MKHELP) >> $(HUGE);     \
	echo '#else' >> $(HUGE);                                \
	$(NROFF) $(MANPAGE) | $(PERL) $(MKHELP) -c >> $(HUGE);  \
	echo '#endif /* HAVE_LIBZ */' >> $(HUGE) )
else # HAVE_LIBZ
# This generates the tool_hugehelp.c file uncompressed only
$(HUGE): $(MANPAGE) $(MKHELP)
	$(HUGECMD)(echo '#include "tool_setup.h"' > $(HUGE);    \
	$(NROFF) $(MANPAGE) | $(PERL) $(MKHELP) >> $(HUGE) )
endif

else # USE_MANUAL
# built-in manual has been disabled, make a blank file
$(HUGE):
	$(HUGECMD)(echo "/* built-in manual is disabled, blank function */" > $(HUGE); \
	echo '#include "tool_hugehelp.h"' >> $(HUGE); \
	echo "void hugehelp(void) {}" >>$(HUGE) )
endif

# ignore tool_hugehelp.c since it is generated source code and it plays
# by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	-W$(srcdir)/tool_hugehelp.c $(srcdir)/*.[ch])

if CURLDEBUG
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif

# disable the tests that are mostly causing false positives
TIDYFLAGS=-checks=-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-optin.performance.Padding,-clang-analyzer-valist.Uninitialized,-clang-analyzer-core.NonNullParamChecker,-clang-analyzer-core.NullDereference

TIDY:=clang-tidy

tidy:
	$(TIDY) $(CURL_CFILES) $(TIDYFLAGS) -- $(curl_CPPFLAGS) $(CPPFLAGS) -DHAVE_CONFIG_H

listhelp:
	(cd $(top_srcdir)/docs/cmdline-opts && ./gen.pl listhelp *.d) > tool_listhelp.c
