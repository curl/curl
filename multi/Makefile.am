#
# $Id$
#

INCLUDES = -I$(top_srcdir)/include

noinst_PROGRAMS = app single double

app_SOURCES = app.c
app_LDADD = ../lib/libcurl.la
app_DEPENDENCIES = ../lib/libcurl.la

single_SOURCES = single.c
single_LDADD = ../lib/libcurl.la
single_DEPENDENCIES = ../lib/libcurl.la

double_SOURCES = double.c
double_LDADD = ../lib/libcurl.la
double_DEPENDENCIES = ../lib/libcurl.la

AUTOMAKE_OPTIONS = foreign no-dependencies
