#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
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
check_PROGRAMS = 10-at-a-time anyauthput cookie_interface debug fileupload \
  fopen ftpget ftpgetresp ftpupload getinfo getinmemory http-post httpput  \
  https multi-app multi-debugcallback multi-double multi-post multi-single \
  persistant post-callback postit2 sepheaders simple simplepost simplessl  \
  sendrecv httpcustomheader certinfo chkspeed ftpgetinfo ftp-wildcard      \
  smtp-mail smtp-mime smtp-multi smtp-ssl smtp-tls smtp-vrfy smtp-expn     \
  rtsp externalsocket resolve progressfunc pop3-retr pop3-list pop3-uidl   \
  pop3-dele pop3-top pop3-stat pop3-noop pop3-ssl pop3-tls pop3-multi      \
  imap-list imap-lsub imap-fetch imap-store imap-append imap-examine       \
  imap-search imap-create imap-delete imap-copy imap-noop imap-ssl         \
  imap-tls imap-multi url2file sftpget ftpsget postinmemory http2-download \
  http2-upload http2-serverpush getredirect ftpuploadfrommem               \
  ftpuploadresume sslbackend postit2-formadd multi-formadd

# These examples require external dependencies that may not be commonly
# available on POSIX systems, so don't bother attempting to compile them here.
COMPLICATED_EXAMPLES = curlgtk.c curlx.c htmltitle.cpp cacertinmem.c       \
  ghiper.c hiperfifo.c htmltidy.c multithread.c          \
  opensslthreadlock.c sampleconv.c synctime.c threaded-ssl.c evhiperfifo.c \
  smooth-gtk-thread.c version-check.pl href_extractor.c asiohiper.cpp      \
  multi-uv.c xmlstream.c usercertinmem.c sessioninfo.c
