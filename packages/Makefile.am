#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
SUBDIRS = vms

EXTRA_DIST = README \
  DOS/README \
  DOS/common.dj \
  OS400/README.OS400 \
  OS400/ccsidcurl.c \
  OS400/ccsidcurl.h \
  OS400/chkstrings.c \
  OS400/curl.inc.in \
  OS400/initscript.sh \
  OS400/make-include.sh \
  OS400/make-lib.sh \
  OS400/make-src.sh \
  OS400/make-tests.sh \
  OS400/makefile.sh \
  OS400/os400sys.c \
  OS400/os400sys.h \
  Android/Android.mk

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/lib/checksrc.pl -D$(srcdir) $(srcdir)/OS400/*.[ch])
