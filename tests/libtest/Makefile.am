#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

EXTRA_DIST = test75.pl test307.pl test610.pl test613.pl

# files used only in some libcurl test programs
TESTUTIL = testutil.c testutil.h

# these files are used in every single test program below
SUPPORTFILES = first.c test.h

# These are all libcurl test programs
noinst_PROGRAMS = lib500 lib501 lib502 lib503 lib504 lib505 lib506	\
  lib507 lib508 lib509 lib510 lib511 lib512 lib513 lib514 lib515 lib516	\
  lib517 lib518 lib519 lib520 lib521 lib523 lib524 lib525 lib526 lib527	\
  lib529 lib530 lib532 lib533 lib536 lib537

# Dependencies (may need to be overriden)
LIBTEST_LIBS = $(LIBDIR)/libcurl.la
DEPENDENCIES = $(LIBDIR)/libcurl.la

lib500_SOURCES = lib500.c $(SUPPORTFILES)
lib500_DEPENDENCIES = $(DEPENDENCIES)
lib500_LDADD = $(LIBTEST_LIBS)

lib501_SOURCES = lib501.c $(SUPPORTFILES)
lib501_DEPENDENCIES = $(DEPENDENCIES)
lib501_LDADD = $(LIBTEST_LIBS)

lib502_SOURCES = lib502.c $(SUPPORTFILES) $(TESTUTIL)
lib502_DEPENDENCIES = $(DEPENDENCIES)
lib502_LDADD = $(LIBTEST_LIBS)

lib503_SOURCES = lib503.c $(SUPPORTFILES) $(TESTUTIL)
lib503_DEPENDENCIES = $(DEPENDENCIES)
lib503_LDADD = $(LIBTEST_LIBS)

lib504_SOURCES = lib504.c $(SUPPORTFILES) $(TESTUTIL)
lib504_DEPENDENCIES = $(DEPENDENCIES)
lib504_LDADD = $(LIBTEST_LIBS)

lib505_SOURCES = lib505.c $(SUPPORTFILES)
lib505_DEPENDENCIES = $(DEPENDENCIES)
lib505_LDADD = $(LIBTEST_LIBS)

lib506_SOURCES = lib506.c $(SUPPORTFILES)
lib506_DEPENDENCIES = $(DEPENDENCIES)
lib506_LDADD = $(LIBTEST_LIBS)

lib507_SOURCES = lib507.c $(SUPPORTFILES) $(TESTUTIL)
lib507_DEPENDENCIES = $(DEPENDENCIES)
lib507_LDADD = $(LIBTEST_LIBS)

lib508_SOURCES = lib508.c $(SUPPORTFILES)
lib508_DEPENDENCIES = $(DEPENDENCIES)
lib508_LDADD = $(LIBTEST_LIBS)

lib509_SOURCES = lib509.c $(SUPPORTFILES) $(TESTUTIL)
lib509_DEPENDENCIES = $(DEPENDENCIES)
lib509_LDADD = $(LIBTEST_LIBS)

lib510_SOURCES = lib510.c $(SUPPORTFILES)
lib510_DEPENDENCIES = $(DEPENDENCIES)
lib510_LDADD = $(LIBTEST_LIBS)

lib511_SOURCES = lib511.c $(SUPPORTFILES)
lib511_DEPENDENCIES = $(DEPENDENCIES)
lib511_LDADD = $(LIBTEST_LIBS)

lib512_SOURCES = lib512.c $(SUPPORTFILES)
lib512_DEPENDENCIES = $(DEPENDENCIES)
lib512_LDADD = $(LIBTEST_LIBS)

lib513_SOURCES = lib513.c $(SUPPORTFILES)
lib513_DEPENDENCIES = $(DEPENDENCIES)
lib513_LDADD = $(LIBTEST_LIBS)

lib514_SOURCES = lib514.c $(SUPPORTFILES)
lib514_DEPENDENCIES = $(DEPENDENCIES)
lib514_LDADD = $(LIBTEST_LIBS)

lib515_SOURCES = lib515.c $(SUPPORTFILES)
lib515_DEPENDENCIES = $(DEPENDENCIES)
lib515_LDADD = $(LIBTEST_LIBS)

lib516_SOURCES = lib516.c $(SUPPORTFILES)
lib516_DEPENDENCIES = $(DEPENDENCIES)
lib516_LDADD = $(LIBTEST_LIBS)

lib517_SOURCES = lib517.c $(SUPPORTFILES)
lib517_DEPENDENCIES = $(DEPENDENCIES)
lib517_LDADD = $(LIBTEST_LIBS)

lib518_SOURCES = lib518.c $(SUPPORTFILES)
lib518_DEPENDENCIES = $(DEPENDENCIES)
lib518_LDADD = $(LIBTEST_LIBS)

lib519_SOURCES = lib519.c $(SUPPORTFILES)
lib519_DEPENDENCIES = $(DEPENDENCIES)
lib519_LDADD = $(LIBTEST_LIBS)

lib520_SOURCES = lib520.c $(SUPPORTFILES)
lib520_DEPENDENCIES = $(DEPENDENCIES)
lib520_LDADD = $(LIBTEST_LIBS)

lib521_SOURCES = lib521.c $(SUPPORTFILES)
lib521_DEPENDENCIES = $(DEPENDENCIES)
lib521_LDADD = $(LIBTEST_LIBS)

lib523_SOURCES = lib523.c $(SUPPORTFILES)
lib523_DEPENDENCIES = $(DEPENDENCIES)
lib523_LDADD = $(LIBTEST_LIBS)

lib524_SOURCES = lib524.c $(SUPPORTFILES)
lib524_DEPENDENCIES = $(DEPENDENCIES)
lib524_LDADD = $(LIBTEST_LIBS)

lib525_SOURCES = lib525.c $(SUPPORTFILES) $(TESTUTIL)
lib525_DEPENDENCIES = $(DEPENDENCIES)
lib525_LDADD = $(LIBTEST_LIBS)

lib526_SOURCES = lib526.c $(SUPPORTFILES) $(TESTUTIL)
lib526_CFLAGS = -DLIB526
lib526_DEPENDENCIES = $(DEPENDENCIES)
lib526_LDADD = $(LIBTEST_LIBS)

lib527_SOURCES = lib526.c $(SUPPORTFILES) $(TESTUTIL)
lib527_CFLAGS = -DLIB527
lib527_DEPENDENCIES = $(DEPENDENCIES)
lib527_LDADD = $(LIBTEST_LIBS)

lib529_SOURCES = lib525.c $(SUPPORTFILES) $(TESTUTIL)
lib529_CFLAGS = -DLIB529
lib529_DEPENDENCIES = $(DEPENDENCIES)
lib529_LDADD = $(LIBTEST_LIBS)

lib530_SOURCES = lib530.c $(SUPPORTFILES) $(TESTUTIL)
lib530_CFLAGS = -DLIB530
lib530_DEPENDENCIES = $(DEPENDENCIES)
lib530_LDADD = $(LIBTEST_LIBS)

lib532_SOURCES = lib526.c $(SUPPORTFILES) $(TESTUTIL)
lib532_CFLAGS = -DLIB532
lib532_DEPENDENCIES = $(DEPENDENCIES)
lib532_LDADD = $(LIBTEST_LIBS)

lib533_SOURCES = lib533.c $(SUPPORTFILES) $(TESTUTIL)
lib533_DEPENDENCIES = $(DEPENDENCIES)
lib533_LDADD = $(LIBTEST_LIBS)

lib536_SOURCES = lib536.c $(SUPPORTFILES) $(TESTUTIL)
lib536_DEPENDENCIES = $(DEPENDENCIES)
lib536_LDADD = $(LIBTEST_LIBS)

lib537_SOURCES = lib537.c $(SUPPORTFILES)
lib537_DEPENDENCIES = $(DEPENDENCIES)
lib537_LDADD = $(LIBTEST_LIBS)

