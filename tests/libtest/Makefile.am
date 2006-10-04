#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
AUTOMAKE_OPTIONS = foreign nostdinc

# $(top_srcdir)/include/curl is for the main curl include files, to make it
# easier to include this specific set of curl headers, and NOT the ones
# possibly already installed in the system.
# -I$(top_srcdir)/lib is for the setup.h file, included by test.h
# -I$(top_builddir)/lib is for the config.h file, possibly included by the
# setup.h file

INCLUDES = -I$(top_srcdir)/include/curl \
           -I$(top_builddir)/lib   \
           -I$(top_srcdir)/lib 

LIBDIR = $(top_builddir)/lib

# these files are used in every single test program below
SUPPORTFILES = first.c test.h

# These are all libcurl test programs
noinst_PROGRAMS = lib500 lib501 lib502 lib503 lib504 lib505 lib506	\
  lib507 lib508 lib509 lib510 lib511 lib512 lib513 lib514 lib515 lib516	\
  lib517 lib518 lib519 lib520 lib521 lib523 lib524 lib525 lib526 lib527	\
  lib529 lib530 lib532

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

lib508_SOURCES = lib508.c $(SUPPORTFILES)
lib508_LDADD = $(LIBDIR)/libcurl.la
lib508_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib509_SOURCES = lib509.c $(SUPPORTFILES)
lib509_LDADD = $(LIBDIR)/libcurl.la
lib509_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib510_SOURCES = lib510.c $(SUPPORTFILES)
lib510_LDADD = $(LIBDIR)/libcurl.la
lib510_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib511_SOURCES = lib511.c $(SUPPORTFILES)
lib511_LDADD = $(LIBDIR)/libcurl.la
lib511_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib512_SOURCES = lib512.c $(SUPPORTFILES)
lib512_LDADD = $(LIBDIR)/libcurl.la
lib512_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib513_SOURCES = lib513.c $(SUPPORTFILES)
lib513_LDADD = $(LIBDIR)/libcurl.la
lib513_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib514_SOURCES = lib514.c $(SUPPORTFILES)
lib514_LDADD = $(LIBDIR)/libcurl.la
lib514_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib515_SOURCES = lib515.c $(SUPPORTFILES)
lib515_LDADD = $(LIBDIR)/libcurl.la
lib515_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib516_SOURCES = lib516.c $(SUPPORTFILES)
lib516_LDADD = $(LIBDIR)/libcurl.la
lib516_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib517_SOURCES = lib517.c $(SUPPORTFILES)
lib517_LDADD = $(LIBDIR)/libcurl.la
lib517_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib518_SOURCES = lib518.c $(SUPPORTFILES)
lib518_LDADD = $(LIBDIR)/libcurl.la
lib518_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib519_SOURCES = lib519.c $(SUPPORTFILES)
lib519_LDADD = $(LIBDIR)/libcurl.la
lib519_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib520_SOURCES = lib520.c $(SUPPORTFILES)
lib520_LDADD = $(LIBDIR)/libcurl.la
lib520_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib521_SOURCES = lib521.c $(SUPPORTFILES)
lib521_LDADD = $(LIBDIR)/libcurl.la
lib521_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib523_SOURCES = lib523.c $(SUPPORTFILES)
lib523_LDADD = $(LIBDIR)/libcurl.la
lib523_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib524_SOURCES = lib524.c $(SUPPORTFILES)
lib524_LDADD = $(LIBDIR)/libcurl.la
lib524_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib525_SOURCES = lib525.c $(SUPPORTFILES)
lib525_LDADD = $(LIBDIR)/libcurl.la
lib525_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib526_SOURCES = lib526.c $(SUPPORTFILES)
lib526_CFLAGS = -DLIB526
lib526_LDADD = $(LIBDIR)/libcurl.la
lib526_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib527_SOURCES = lib526.c $(SUPPORTFILES)
lib527_CFLAGS = -DLIB527
lib527_LDADD = $(LIBDIR)/libcurl.la
lib527_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib529_SOURCES = lib525.c $(SUPPORTFILES)
lib529_CFLAGS = -DLIB529
lib529_LDADD = $(LIBDIR)/libcurl.la
lib529_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib530_SOURCES = lib530.c $(SUPPORTFILES)
lib530_CFLAGS = -DLIB530
lib530_LDADD = $(LIBDIR)/libcurl.la
lib530_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib532_SOURCES = lib526.c $(SUPPORTFILES)
lib532_CFLAGS = -DLIB532
lib532_LDADD = $(LIBDIR)/libcurl.la
lib532_DEPENDENCIES = $(LIBDIR)/libcurl.la
