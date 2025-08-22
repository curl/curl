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

# These are all libcurl example programs to be test compiled
check_PROGRAMS = \
  10-at-a-time \
  address-scope \
  altsvc \
  anyauthput \
  block_ip \
  certinfo \
  chkspeed \
  connect-to \
  cookie_interface \
  debug \
  default-scheme \
  externalsocket \
  fileupload \
  ftp-delete \
  ftp-wildcard \
  ftpget \
  ftpgetinfo \
  ftpgetresp \
  ftpsget \
  ftpupload \
  ftpuploadfrommem \
  ftpuploadresume \
  getinfo \
  getinmemory \
  getredirect \
  getreferrer \
  headerapi \
  hsts-preload \
  http-options \
  http-post \
  http2-download \
  http2-pushinmemory \
  http2-serverpush \
  http2-upload \
  http3 \
  http3-present \
  httpcustomheader \
  httpput \
  httpput-postfields \
  https \
  imap-append \
  imap-authzid \
  imap-copy \
  imap-create \
  imap-delete \
  imap-examine \
  imap-fetch \
  imap-list \
  imap-lsub \
  imap-multi \
  imap-noop \
  imap-search \
  imap-ssl \
  imap-store \
  imap-tls \
  interface \
  ipv6 \
  keepalive \
  localport \
  maxconnects \
  multi-app \
  multi-debugcallback \
  multi-double \
  multi-formadd \
  multi-legacy \
  multi-post \
  multi-single \
  netrc \
  parseurl \
  persistent \
  pop3-authzid \
  pop3-dele \
  pop3-list \
  pop3-multi \
  pop3-noop \
  pop3-retr \
  pop3-ssl \
  pop3-stat \
  pop3-tls \
  pop3-top \
  pop3-uidl \
  post-callback \
  postinmemory \
  postit2 \
  postit2-formadd \
  progressfunc \
  protofeats \
  range \
  resolve \
  rtsp-options \
  sendrecv \
  sepheaders \
  sftpget \
  sftpuploadresume \
  shared-connection-cache \
  simple \
  simplepost \
  simplessl \
  smtp-authzid \
  smtp-expn \
  smtp-mail \
  smtp-mime \
  smtp-multi \
  smtp-ssl \
  smtp-tls \
  smtp-vrfy \
  sslbackend \
  unixsocket \
  url2file \
  urlapi \
  websocket \
  websocket-cb \
  websocket-updown

# These examples require external dependencies that may not be commonly
# available on POSIX systems, so do not bother attempting to compile them here.
COMPLICATED_EXAMPLES = \
  cacertinmem.c \
  crawler.c \
  ephiperfifo.c \
  evhiperfifo.c \
  ghiper.c \
  hiperfifo.c \
  htmltidy.c \
  htmltitle.cpp \
  multi-event.c \
  multi-uv.c \
  multithread.c \
  sessioninfo.c \
  smooth-gtk-thread.c \
  synctime.c \
  threaded-ssl.c \
  usercertinmem.c \
  version-check.pl \
  xmlstream.c
