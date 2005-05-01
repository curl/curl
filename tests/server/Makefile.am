#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# $Id$
###########################################################################

AUTOMAKE_OPTIONS = foreign

INCLUDES = -I$(top_srcdir)/lib -I$(top_srcdir)/include

noinst_PROGRAMS = sws getpart sockfilt

useful = getpart.c getpart.h $(top_srcdir)/lib/strequal.c	\
 $(top_srcdir)/lib/base64.c $(top_srcdir)/lib/mprintf.c		\
 $(top_srcdir)/lib/memdebug.c $(top_srcdir)/lib/timeval.c

sws_SOURCES= sws.c util.c util.h $(useful)
sockfilt_SOURCES = sockfilt.c util.c util.h $(useful)	\
 $(top_srcdir)/lib/inet_pton.c
getpart_SOURCES= testpart.c $(useful)

extra_DIST = base64.pl
