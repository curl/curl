#
# $Id$
#

AUTOMAKE_OPTIONS = foreign nostdinc

# we use srcdir/include for the static global include files
# we use builddir/src for the generated src/config.h file to get found
# we use srcdir/lib for the client-private header files
INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/src -I$(top_srcdir)/src

bin_PROGRAMS = curl #memtest

if HAVE_LIBZ
# libz available, attempt to compress the help data
MKHELPOPT=-c
else
# no libz, don't try to compress
MKHELPOPT=
endif

#memtest_SOURCES = memtest.c
#memtest_LDADD = $(top_srcdir)/lib/libcurl.la

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
	config-amiga.h makefile.amiga

MANPAGE=$(top_srcdir)/docs/curl.1
README=$(top_srcdir)/docs/MANUAL
MKHELP=$(top_srcdir)/src/mkhelp.pl

# This generates the hugehelp.c file
hugehelp.c: $(README) $(MANPAGE)  mkhelp.pl
	rm -f hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP) $(MKHELPOPT) $(README) > hugehelp.c

# for distribution, generate an uncompressed help file!
dist-hook:
	chmod 0644 $(distdir)/hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP) $(README) > $(distdir)/hugehelp.c
