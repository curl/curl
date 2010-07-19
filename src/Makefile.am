#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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
AUTOMAKE_OPTIONS = foreign nostdinc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_builddir)/include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/include for generated curlbuild.h included from lib/setup.h
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_builddir)/src is for curl's generated src/curl_config.h file
# $(top_srcdir)/lib is for libcurl's lib/setup.h and other "borrowed" files
# $(top_srcdir)/src is for curl's src/setup.h and "curl-private" files

INCLUDES = -I$(top_builddir)/include/curl \
           -I$(top_builddir)/include      \
           -I$(top_srcdir)/include        \
           -I$(top_builddir)/lib          \
           -I$(top_builddir)/src          \
           -I$(top_srcdir)/lib            \
           -I$(top_srcdir)/src

bin_PROGRAMS = curl

include Makefile.inc

# This might hold -Werror
CFLAGS += @CURL_CFLAG_EXTRAS@

curl_LDADD = $(top_builddir)/lib/libcurl.la @CURL_LIBS@
curl_DEPENDENCIES = $(top_builddir)/lib/libcurl.la
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
# Use the C locale to ensure that only ASCII characters appear in the
# embedded text.
NROFF=env LC_ALL=C @NROFF@ @MANOPT@ # figured out by the configure script

EXTRA_DIST = mkhelp.pl makefile.dj Makefile.vc6 Makefile.b32 Makefile.m32 \
	Makefile.riscos curl_config.h.in macos/curl.mcp.xml.sit.hqx	  \
	macos/MACINSTALL.TXT macos/src/curl_GUSIConfig.cpp vc6curlsrc.dsp \
	macos/src/macos_main.cpp config-amigaos.h makefile.amiga curl.rc  \
	Makefile.netware Makefile.inc Makefile.Watcom vc6curlsrc.dsw      \
	CMakeLists.txt

MANPAGE=$(top_srcdir)/docs/curl.1
README=$(top_srcdir)/docs/MANUAL
MKHELP=$(top_srcdir)/src/mkhelp.pl
HUGE=hugehelp.c

if USE_MANUAL
# Here are the stuff to create a built-in manual

if HAVE_LIBZ
# This generates the hugehelp.c file in both uncompressed and compressed formats
$(HUGE): $(README) $(MANPAGE)  mkhelp.pl
	echo '#include "setup.h"' > $(HUGE)
	echo '#ifndef HAVE_LIBZ' >> $(HUGE)
	$(NROFF) $(MANPAGE) | $(PERL) $(MKHELP) $(README) >> $(HUGE)
	echo '#else' >> $(HUGE)
	$(NROFF) $(MANPAGE) | $(PERL) $(MKHELP) -c $(README) >> $(HUGE)
	echo '#endif /* HAVE_LIBZ */' >> $(HUGE)
else # HAVE_LIBZ
# This generates the hugehelp.c file uncompressed only
$(HUGE): $(README) $(MANPAGE)  mkhelp.pl
	echo '#include "setup.h"' > $(HUGE)
	$(NROFF) $(MANPAGE) | $(PERL) $(MKHELP) $(README) >> $(HUGE)
endif

else # USE_MANUAL
# built-in manual has been disabled, make a blank file
$(HUGE):
	echo "/* built-in manual is disabled, blank function */" > $(HUGE)
	echo '#include "hugehelp.h"' >> $(HUGE)
	echo "void hugehelp(void) {}" >>$(HUGE)
endif
