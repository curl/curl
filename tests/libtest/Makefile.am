#
# $Id$
#

AUTOMAKE_OPTIONS = foreign nostdinc

INCLUDES = -I$(top_srcdir)/include/curl -I$(top_builddir)/lib

LIBDIR = ../../lib

SUPPORTFILES = first.c test.h

# here are all tools used for running libcurl tests
noinst_PROGRAMS = lib500 lib501 lib502 lib503 lib504 lib505 lib506 lib507

lib500_SOURCES = lib500.c $(SUPPORTFILES)
lib500_LDADD = $(LIBDIR)/libcurl.la
lib500_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib501_SOURCES = lib501.c $(SUPPORTFILES)
lib501_LDADD = $(LIBDIR)/libcurl.la
lib501_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib502_SOURCES = lib502.c $(SUPPORTFILES)
lib502_LDADD = $(LIBDIR)/libcurl.la
lib502_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib503_SOURCES = lib503.c $(SUPPORTFILES)
lib503_LDADD = $(LIBDIR)/libcurl.la
lib503_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib504_SOURCES = lib504.c $(SUPPORTFILES)
lib504_LDADD = $(LIBDIR)/libcurl.la
lib504_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib505_SOURCES = lib505.c $(SUPPORTFILES)
lib505_LDADD = $(LIBDIR)/libcurl.la
lib505_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib506_SOURCES = lib506.c $(SUPPORTFILES)
lib506_LDADD = $(LIBDIR)/libcurl.la
lib506_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib507_SOURCES = lib507.c $(SUPPORTFILES)
lib507_LDADD = $(LIBDIR)/libcurl.la
lib507_DEPENDENCIES = $(LIBDIR)/libcurl.la
