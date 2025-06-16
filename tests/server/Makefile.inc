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
# Shared between CMakeLists.txt and Makefile.am

BUNDLE = servers
BUNDLE_SRC = servers.c

# Files referenced from the bundle source
FIRSTFILES = first.c first.h

# Common files used by test programs
UTILS = getpart.c getpart.h util.c

CURLX_SRCS = \
  ../../lib/curlx/base64.c \
  ../../lib/curlx/inet_pton.c \
  ../../lib/curlx/multibyte.c \
  ../../lib/curlx/nonblock.c \
  ../../lib/curlx/strparse.c \
  ../../lib/curlx/timediff.c \
  ../../lib/curlx/timeval.c \
  ../../lib/curlx/version_win32.c \
  ../../lib/curlx/wait.c \
  ../../lib/curlx/warnless.c \
  ../../lib/curlx/winapi.c

# All test servers
TESTFILES = \
  dnsd.c \
  mqttd.c \
  resolve.c \
  rtspd.c \
  sockfilt.c \
  socksd.c \
  sws.c \
  tftpd.c
