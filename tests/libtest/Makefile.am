#
# $Id$
#

AUTOMAKE_OPTIONS = foreign nostdinc

INCLUDES = -I$(top_srcdir)/include

LIBDIR = ../../lib

# here are all tools used for running libcurl tests
bin_PROGRAMS = lib500 lib501

lib500_SOURCES = lib500.c first.c test.h
lib500_LDADD = $(LIBDIR)/libcurl.la
lib500_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib501_SOURCES = lib501.c first.c test.h
lib501_LDADD = $(LIBDIR)/libcurl.la
lib501_DEPENDENCIES = $(LIBDIR)/libcurl.la

setup:
	for file in lib*.c; do \
	  echo $$file; \
	done
