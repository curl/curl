#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# These are all libcurl example programs to be test compiled
check_PROGRAMS = \
  10-at-a-time \
  altsvc \
  anyauthput \
  certinfo \
  chkspeed \
  cookie_interface \
  debug \
  externalsocket \
  fileupload \
  fopen \
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
  multi-app \
  multi-debugcallback \
  multi-double \
  multi-formadd \
  multi-legacy \
  multi-post \
  multi-single \
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
  resolve \
  rtsp \
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
  url2file \
  urlapi

# These examples require external dependencies that may not be commonly
# available on POSIX systems, so don't bother attempting to compile them here.
COMPLICATED_EXAMPLES = \
  cacertinmem.c \
  crawler.c \
  curlgtk.c \
  curlx.c \
  ephiperfifo.c \
  evhiperfifo.c \
  ghiper.c \
  hiperfifo.c \
  href_extractor.c \
  htmltidy.c \
  htmltitle.cpp \
  multi-event.c \
  multi-uv.c \
  multithread.c \
  opensslthreadlock.c \
  sampleconv.c \
  sessioninfo.c \
  smooth-gtk-thread.c \
  synctime.c \
  threaded-ssl.c \
  usercertinmem.c \
  version-check.pl \
  xmlstream.c
