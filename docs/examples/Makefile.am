#
# $Id$
#

AUTOMAKE_OPTIONS = foreign nostdinc

EXTRA_DIST = README Makefile.example Makefile.inc Makefile.m32 \
	makefile.dj $(COMPLICATED_EXAMPLES)

INCLUDES = -I$(top_srcdir)/include

LIBDIR = $(top_builddir)/lib

if STATICLIB
# we need this define when building with a static lib on Windows
STATICCPPFLAGS = -DCURL_STATICLIB
endif

CPPFLAGS = -DCURL_NO_OLDIES $(STATICCPPFLAGS)

# Dependencies
LDADD = $(LIBDIR)/libcurl.la

# Makefile.inc provides the noinst_PROGRAMS and COMPLICATED_EXAMPLES defines
include Makefile.inc


