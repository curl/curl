#
# $Id$
#

# Some flags needed when trying to cause warnings ;-)
# CFLAGS = -Wall -pedantic
CPPFLAGS = -DGLOBURL -DCURL_SEPARATORS

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = curl

curl_SOURCES = main.c hugehelp.c urlglob.c
curl_LDADD = ../lib/libcurl.a
curl_DEPENDENCIES = ../lib/libcurl.a
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
NROFF=@NROFF@

EXTRA_DIST = mkhelp.pl Makefile.vc6

AUTOMAKE_OPTIONS = foreign no-dependencies

# This generates the hugehelp.c file
hugehelp.c: $(top_srcdir)/README.curl $(top_srcdir)/curl.1 mkhelp.pl
	rm -f hugehelp.c
	$(NROFF) -man $(top_srcdir)/curl.1 | $(PERL) $(top_srcdir)/src/mkhelp.pl $(top_srcdir)/README.curl > hugehelp.c
