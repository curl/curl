#
# $Id$
#

AUTOMAKE_OPTIONS = foreign nostdinc

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = curl #memtest

#memtest_SOURCES = memtest.c
#memtest_LDADD = $(top_srcdir)/lib/libcurl.la

curl_SOURCES = main.c hugehelp.c urlglob.c writeout.c setup.h \
	config-win32.h \
	config-mac.h \
	config-vms.h \
	urlglob.h \
	version.h \
	writeout.h \
	config-win32.h \
	config-mac.h \
	config-vms.h	

curl_LDADD = ../lib/libcurl.la
curl_DEPENDENCIES = ../lib/libcurl.la
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
NROFF=@NROFF@

EXTRA_DIST = mkhelp.pl curlmsg.msg \
	Makefile.vc6 Makefile.b32 Makefile.m32 config.h.in \
	macos/curl.mcp.xml.sit.hqx \
	macos/MACINSTALL.TXT \
	macos/src/curl_GUSIConfig.cpp \
	macos/src/macos_main.cpp

MANPAGE=$(top_srcdir)/docs/curl.1
README=$(top_srcdir)/docs/MANUAL
MKHELP=$(top_srcdir)/src/mkhelp.pl

# This generates the hugehelp.c file
hugehelp.c: $(README) $(MANPAGE)  mkhelp.pl
	rm -f hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP)  $(README) > hugehelp.c
