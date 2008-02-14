AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libcares.la

man_MANS = $(MANPAGES)

MSVCFILES = vc/adig/adig.dep vc/adig/adig.dsp vc/vc.dsw vc/ahost/ahost.dep \
 vc/ahost/ahost.dsp vc/areslib/areslib.dep vc/areslib/areslib.dsp	   \
 vc/areslib/areslib.dsw

if DEBUGBUILD
PROGS =
else
PROGS = ahost adig acountry
endif

noinst_PROGRAMS =$(PROGS)

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = AUTHORS CHANGES README.cares Makefile.inc Makefile.dj \
 Makefile.m32 Makefile.netware Makefile.vc6 adig.c ahost.c $(man_MANS) \
 $(MSVCFILES) config-win32.h RELEASE-NOTES libcares.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcares.pc

VER=-version-info 2:0:0
# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# If either revision or age are omitted, they default to 0. Also note that age
# must be less than or equal to the current interface number.
#
# Here are a set of rules to help you update your library version information: 
#
# 1.Start with version information of 0:0:0 for each libtool library.
#
# 2.Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
#
# 3.If the library source code has changed at all since the last update, then
# increment revision (c:r+1:a)
#
# 4.If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0. (c+1:r=0:a)
#
# 5.If any interfaces have been added since the last public release, then
# increment age. (c:r:a+1)
#
# 6.If any interfaces have been removed since the last public release, then
# set age to 0. (c:r:a=0)
#

if NO_UNDEFINED
# The -no-undefined flag is crucial for this to build fine on some platforms
UNDEF = -no-undefined
endif


libcares_la_LDFLAGS = $(UNDEF) $(VER)

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcares_la_SOURCES = $(CSOURCES) $(HHEADERS)

# where to install the c-ares headers
libcares_ladir = $(includedir)
# what headers to install on 'make install':
libcares_la_HEADERS = ares.h ares_version.h ares_dns.h

ahost_SOURCES = ahost.c ares_getopt.c
ahost_LDADD = $(top_builddir)/$(lib_LTLIBRARIES)

adig_SOURCES = adig.c ares_getopt.c
adig_LDADD = $(top_builddir)/$(lib_LTLIBRARIES)

acountry_SOURCES = acountry.c ares_getopt.c
acountry_LDADD = $(top_builddir)/$(lib_LTLIBRARIES)

# Make files named *.dist replace the file without .dist extension
dist-hook:
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)
