#
# $Id$
#

# Some flags needed when trying to cause warnings ;-)
# CFLAGS = -Wall -pedantic
#CPPFLAGS = -DGLOBURL -DCURL_SEPARATORS

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = curl

curl_SOURCES = main.c hugehelp.c urlglob.c
curl_LDADD = $(top_srcdir)/lib/libcurl.a
curl_DEPENDENCIES = $(top_srcdir)/lib/libcurl.a
BUILT_SOURCES = hugehelp.c
CLEANFILES = hugehelp.c
NROFF=@NROFF@

EXTRA_DIST = mkhelp.pl Makefile.vc6

AUTOMAKE_OPTIONS = foreign no-dependencies

MANPAGE=$(top_srcdir)/docs/curl.1
README=$(top_srcdir)/docs/README.curl
MKHELP=$(top_srcdir)/src/mkhelp.pl

# This generates the hugehelp.c file
hugehelp.c: $(README) $(MANPAGE)  mkhelp.pl
	rm -f hugehelp.c
	$(NROFF) -man $(MANPAGE) | $(PERL) $(MKHELP)  $(README) > hugehelp.c
