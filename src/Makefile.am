#
# $Id$
#

# Some flags needed when trying to cause warnings ;-)
# CFLAGS = -g -DMALLOCDEBUG # -Wall -pedantic
#CPPFLAGS = -DGLOBURL -DCURL_SEPARATORS

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = curl #memtest

noinst_HEADERS = setup.h \
	config-win32.h \
	urlglob.h \
	version.h \
	writeout.h

#memtest_SOURCES = memtest.c
#memtest_LDADD = $(top_srcdir)/lib/libcurl.la

curl_SOURCES = main.c hugehelp.c urlglob.c writeout.c
curl_LDADD = ../lib/libcurl.la
curl_DEPENDENCIES = ../lib/libcurl.la
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
NROFF=@NROFF@

EXTRA_DIST = mkhelp.pl config-win32.h curlmsg.msg\
	Makefile.vc6 Makefile.b32 Makefile.m32 config.h.in

AUTOMAKE_OPTIONS = foreign no-dependencies

MANPAGE=$(top_srcdir)/docs/curl.1
README=$(top_srcdir)/docs/MANUAL
MKHELP=$(top_srcdir)/src/mkhelp.pl

# This generates the hugehelp.c file
hugehelp.c: $(README) $(MANPAGE)  mkhelp.pl
	rm -f hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP)  $(README) > hugehelp.c
