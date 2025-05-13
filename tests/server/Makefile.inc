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

resolve_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) \
  resolve.c
resolve_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
resolve_CFLAGS = $(AM_CFLAGS)

rtspd_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) \
  server_sockaddr.h \
  rtspd.c
rtspd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
rtspd_CFLAGS = $(AM_CFLAGS)

sockfilt_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) $(INET_PTON) \
  server_sockaddr.h \
  sockfilt.c
sockfilt_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
sockfilt_CFLAGS = $(AM_CFLAGS)

socksd_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) $(INET_PTON) \
  server_sockaddr.h \
  socksd.c
socksd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
socksd_CFLAGS = $(AM_CFLAGS)

mqttd_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) \
  server_sockaddr.h \
  mqttd.c
mqttd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
mqttd_CFLAGS = $(AM_CFLAGS)

sws_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) $(INET_PTON) \
  server_sockaddr.h \
  sws.c
sws_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
sws_CFLAGS = $(AM_CFLAGS)

tftpd_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) \
  server_sockaddr.h \
  tftpd.c \
  tftp.h
tftpd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
tftpd_CFLAGS = $(AM_CFLAGS)

dnsd_SOURCES = $(MEMDEBUG) $(CURLX_SRCS) $(CURLX_HDRS) $(UTIL) \
  dnsd.c
dnsd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
dnsd_CFLAGS = $(AM_CFLAGS)
