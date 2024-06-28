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

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif
AM_CPPFLAGS += -DBUILDING_CURL

include Makefile.inc

# CURL_FILES comes from Makefile.inc
curl_SOURCES = $(CURL_FILES)
if HAVE_WINDRES
curl_SOURCES += $(CURL_RCFILES)
$(CURL_RCFILES): tool_version.h
endif

curl_LDFLAGS = $(AM_LDFLAGS) $(CURL_LDFLAGS_BIN)

# This might hold -Werror
CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

if USE_EXPLICIT_LIB_DEPS
curl_LDADD = $(top_builddir)/lib/libcurl.la @LIBCURL_LIBS@
else
curl_LDADD = $(top_builddir)/lib/libcurl.la @SSL_LIBS@ @ZLIB_LIBS@ @CURL_NETWORK_AND_TIME_LIBS@
endif

# if unit tests are enabled, build a static library to link them with
if BUILD_UNITTESTS
noinst_LTLIBRARIES = libcurltool.la
libcurltool_la_CPPFLAGS = $(AM_CPPFLAGS) \
                          -DCURL_STATICLIB -DUNITTESTS
libcurltool_la_CFLAGS =
libcurltool_la_LDFLAGS = -static $(LINKFLAGS)
libcurltool_la_SOURCES = $(CURL_FILES)
endif

CLEANFILES = tool_hugehelp.c
# Use the C locale to ensure that only ASCII characters appear in the
# embedded text.
NROFF=env LC_ALL=C @NROFF@ @MANOPT@ 2>/dev/null # figured out by the configure script

EXTRA_DIST = mkhelp.pl \
 Makefile.mk curl.rc Makefile.inc CMakeLists.txt .checksrc

# Use absolute directory to disable VPATH
ASCIIPAGE=$(top_builddir)/docs/cmdline-opts/curl.txt
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

$(ASCIIPAGE):
	cd $(top_builddir)/docs && $(MAKE)

if HAVE_LIBZ
# This generates the tool_hugehelp.c file in both uncompressed and
# compressed formats.
$(HUGE): $(ASCIIPAGE) $(MKHELP)
	$(HUGECMD) (echo '#include "tool_setup.h"' > $(HUGE);   \
	echo '#ifndef HAVE_LIBZ' >> $(HUGE);                    \
	$(PERL) $(MKHELP) < $(ASCIIPAGE) >> $(HUGE);     \
	echo '#else' >> $(HUGE);                                \
	$(PERL) $(MKHELP) -c < $(ASCIIPAGE) >> $(HUGE);  \
	echo '#endif /* HAVE_LIBZ */' >> $(HUGE) )
else # HAVE_LIBZ
# This generates the tool_hugehelp.c file uncompressed only
$(HUGE): $(ASCIIPAGE) $(MKHELP)
	$(HUGECMD)(echo '#include "tool_setup.h"' > $(HUGE);    \
	$(PERL) $(MKHELP) < $(ASCIIPAGE) >> $(HUGE) )
endif

else # USE_MANUAL
# built-in manual has been disabled, make a blank file
$(HUGE):
	echo '#include "tool_hugehelp.h"' >> $(HUGE)
endif

# ignore tool_hugehelp.c since it is generated source code and it plays
# by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	-W$(srcdir)/tool_hugehelp.c $(srcdir)/*.[ch])

if DEBUGBUILD
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif

# disable the tests that are mostly causing false positives
TIDYFLAGS=-checks=-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-optin.performance.Padding,-clang-analyzer-valist.Uninitialized,-clang-analyzer-core.NonNullParamChecker,-clang-analyzer-core.NullDereference

TIDY:=clang-tidy

tidy:
	$(TIDY) $(CURL_CFILES) $(TIDYFLAGS) -- $(curl_CPPFLAGS) $(CPPFLAGS) -DHAVE_CONFIG_H

listhelp:
	(cd $(top_srcdir)/docs/cmdline-opts && make listhelp)

if HAVE_WINDRES
.rc.o:
	$(RC) -I$(top_srcdir)/include -DCURL_EMBED_MANIFEST $(RCFLAGS) -i $< -o $@
endif
