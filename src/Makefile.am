#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# we use srcdir/src for "private" includes
# we use srcdir/include for the static global include files
# we use builddir/src for the generated include files to get found
# we use srcdir/lib for the header files we "borrow" from the lib

INCLUDES = -I$(top_srcdir)/include \
           -I$(top_builddir)/lib   \
           -I$(top_builddir)/src   \
           -I$(top_srcdir)/lib     \
           -I$(top_srcdir)/src

bin_PROGRAMS = curl

include Makefile.inc

curl_LDADD = ../lib/libcurl.la @CURL_LIBS@
curl_DEPENDENCIES = ../lib/libcurl.la
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
# Use the C locale to ensure that only ASCII characters appear in the
# embedded text.
NROFF=env LC_ALL=C @NROFF@ @MANOPT@ # figured out by the configure script

EXTRA_DIST = mkhelp.pl makefile.dj Makefile.vc6 Makefile.b32 Makefile.m32 \
	Makefile.riscos config.h.in macos/curl.mcp.xml.sit.hqx		  \
	macos/MACINSTALL.TXT macos/src/curl_GUSIConfig.cpp		  \
	macos/src/macos_main.cpp config-amigaos.h makefile.amiga curl.rc  \
	Makefile.netware Makefile.inc Makefile.Watcom

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
