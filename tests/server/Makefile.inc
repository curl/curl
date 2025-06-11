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

SERVERPROGS = resolve rtspd sockfilt sws tftpd socksd mqttd dnsd

MEMDEBUG = \
  ../../lib/memdebug.c \
  ../../lib/memdebug.h

CURLX_SRCS = \
  ../../lib/curlx/base64.c \
  ../../lib/curlx/multibyte.c \
  ../../lib/curlx/nonblock.c \
  ../../lib/curlx/strparse.c \
  ../../lib/curlx/timediff.c \
  ../../lib/curlx/timeval.c \
  ../../lib/curlx/version_win32.c \
  ../../lib/curlx/warnless.c \
  ../../lib/curlx/winapi.c

CURLX_HDRS = \
  ../../lib/curlx/base64.h \
  ../../lib/curlx/curlx.h \
  ../../lib/curlx/multibyte.h \
  ../../lib/curlx/nonblock.h \
  ../../lib/curlx/timediff.h \
  ../../lib/curlx/timeval.h \
  ../../lib/curlx/version_win32.h \
  ../../lib/curlx/warnless.h \
  ../../lib/curlx/winapi.h

UTIL = \
  getpart.c \
  getpart.h \
  util.c \
  util.h \
  server_setup.h

FIRSTFILES = \
  first.c \
  first.h

INET_PTON = \
  ../../lib/curlx/inet_pton.c

resolve_SOURCES = resolve.c
rtspd_SOURCES = server_sockaddr.h rtspd.c
sockfilt_SOURCES = server_sockaddr.h sockfilt.c
socksd_SOURCES = server_sockaddr.h socksd.c
mqttd_SOURCES = server_sockaddr.h mqttd.c
sws_SOURCES = server_sockaddr.h sws.c
tftpd_SOURCES = server_sockaddr.h tftpd.c tftp.h
dnsd_SOURCES = dnsd.c
