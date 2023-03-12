#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/src            \
              -I$(top_srcdir)/tests/libtest

EXTRA_DIST = Makefile.inc CMakeLists.txt README.md

CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

LDADD = $(top_builddir)/src/libcurltool.la   \
        $(top_builddir)/lib/libcurlu.la      \
        @LDFLAGS@ @LIBCURL_LIBS@ @NSS_LIBS@

AM_CPPFLAGS += -DCURL_STATICLIB -DUNITTESTS

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)@PERL@ $(top_srcdir)/scripts/checksrc.pl $(srcdir)/*.[ch]

# Makefile.inc provides neat definitions
include Makefile.inc

if BUILD_UNITTESTS
noinst_PROGRAMS = $(UNITPROGS)
else
noinst_PROGRAMS =
endif

unit1300_SOURCES = unit1300.c $(UNITFILES)

unit1302_SOURCES = unit1302.c $(UNITFILES)

unit1303_SOURCES = unit1303.c $(UNITFILES)

unit1304_SOURCES = unit1304.c $(UNITFILES)

unit1305_SOURCES = unit1305.c $(UNITFILES)

unit1307_SOURCES = unit1307.c $(UNITFILES)

unit1308_SOURCES = unit1308.c $(UNITFILES)

unit1309_SOURCES = unit1309.c $(UNITFILES)

unit1323_SOURCES = unit1323.c $(UNITFILES)

unit1330_SOURCES = unit1330.c $(UNITFILES)

unit1394_SOURCES = unit1394.c $(UNITFILES)
unit1394_LDADD = $(top_builddir)/lib/libcurl.la @LIBCURL_LIBS@
unit1394_LDFLAGS = $(top_builddir)/src/libcurltool.la
unit1394_LIBS =

unit1395_SOURCES = unit1395.c $(UNITFILES)

unit1396_SOURCES = unit1396.c $(UNITFILES)

unit1397_SOURCES = unit1397.c $(UNITFILES)

unit1398_SOURCES = unit1398.c $(UNITFILES)

unit1399_SOURCES = unit1399.c $(UNITFILES)

unit1600_SOURCES = unit1600.c $(UNITFILES)

unit1601_SOURCES = unit1601.c $(UNITFILES)

unit1602_SOURCES = unit1602.c $(UNITFILES)

unit1603_SOURCES = unit1603.c $(UNITFILES)

unit1604_SOURCES = unit1604.c $(UNITFILES)

unit1605_SOURCES = unit1605.c $(UNITFILES)

unit1606_SOURCES = unit1606.c $(UNITFILES)

unit1607_SOURCES = unit1607.c $(UNITFILES)

unit1608_SOURCES = unit1608.c $(UNITFILES)

unit1609_SOURCES = unit1609.c $(UNITFILES)

unit1610_SOURCES = unit1610.c $(UNITFILES)

unit1611_SOURCES = unit1611.c $(UNITFILES)

unit1612_SOURCES = unit1612.c $(UNITFILES)

unit1614_SOURCES = unit1614.c $(UNITFILES)

unit1620_SOURCES = unit1620.c $(UNITFILES)

unit1621_SOURCES = unit1621.c $(UNITFILES)
unit1621_LDADD = $(top_builddir)/src/libcurltool.la $(top_builddir)/lib/libcurl.la @NSS_LIBS@

unit1650_SOURCES = unit1650.c $(UNITFILES)

unit1651_SOURCES = unit1651.c $(UNITFILES)

unit1652_SOURCES = unit1652.c $(UNITFILES)

unit1653_SOURCES = unit1653.c $(UNITFILES)

unit1654_SOURCES = unit1654.c $(UNITFILES)

unit1655_SOURCES = unit1655.c $(UNITFILES)

unit1660_SOURCES = unit1660.c $(UNITFILES)

unit1661_SOURCES = unit1661.c $(UNITFILES)

unit2600_SOURCES = unit2600.c $(UNITFILES)

unit3200_SOURCES = unit3200.c $(UNITFILES)
