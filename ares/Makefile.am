AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libcares.la

man_MANS = $(MANPAGES)

MSVCFILES = vc/adig/adig.dep vc/adig/adig.dsp vc/adig/adig.mak	\
 vc/adig/adig.plg vc/vc.dsw vc/ahost/ahost.dep vc/ahost/ahost.dsp	\
 vc/ahost/ahost.mak vc/ahost/ahost.plg vc/areslib/areslib.dep		\
 vc/areslib/areslib.dsp vc/areslib/areslib.mak vc/areslib/areslib.plg

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = CHANGES README.cares Makefile.inc adig.c ahost.c $(man_MANS) \
 $(MSVCFILES)


VER=-version-info 0:0:0
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

libcares_la_LDFLAGS = $(VER)

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcares_la_SOURCES = $(CSOURCES) $(HHEADERS)

# where to install the c-ares headers
libcares_ladir = $(includedir)
# what headers to install on 'make install':
libcares_la_HEADERS = ares.h ares_version.h
