#############################################################################
#                                  _   _ ____  _     
#  Project                     ___| | | |  _ \| |    
#                             / __| | | | |_) | |    
#                            | (__| |_| |  _ <| |___ 
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# In order to be useful for every potential user, curl and libcurl are
# dual-licensed under the MPL and the MIT/X-derivate licenses.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the MPL or the MIT/X-derivate
# licenses. You may pick one of these licenses.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# $Id$
#############################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

# we use srcdir/include for the static global include files
# we use builddir/src for the generated src/config.h file to get found
# we use srcdir/lib for the client-private header files
INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/src -I$(top_srcdir)/src

bin_PROGRAMS = curl #memtest

curl_SOURCES = main.c hugehelp.c urlglob.c writeout.c setup.h \
	config-win32.h config-mac.h config-vms.h config-riscos.h \
	urlglob.h version.h writeout.h writeenv.c writeenv.h \
	getpass.c getpass.h homedir.c homedir.h

curl_LDADD = ../lib/libcurl.la
curl_DEPENDENCIES = ../lib/libcurl.la
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
NROFF=@NROFF@

EXTRA_DIST = mkhelp.pl curlmsg.msg makefile.dj \
	Makefile.vc6 Makefile.b32 Makefile.m32 Makefile.riscos config.h.in \
	macos/curl.mcp.xml.sit.hqx \
	macos/MACINSTALL.TXT \
	macos/src/curl_GUSIConfig.cpp \
	macos/src/macos_main.cpp curlmsg.h curlmsg.sdl curlmsg_vms.h \
	config-amigaos.h makefile.amiga

MANPAGE=$(top_srcdir)/docs/curl.1
README=$(top_srcdir)/docs/MANUAL
MKHELP=$(top_srcdir)/src/mkhelp.pl

if HAVE_LIBZ
# This generates the hugehelp.c file in both uncompressed and compressed formats
hugehelp.c: $(README) $(MANPAGE)  mkhelp.pl
	echo '#include "config.h"' > hugehelp.c
	echo '#ifndef HAVE_LIBZ' >> hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP) $(README) >> hugehelp.c
	echo '#else' >> hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP) -c $(README) >> hugehelp.c
	echo '#endif /* HAVE_LIBZ */' >> hugehelp.c
else
# This generates the hugehelp.c file uncompressed only
hugehelp.c: $(README) $(MANPAGE)  mkhelp.pl
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP) $(README) > hugehelp.c
endif

