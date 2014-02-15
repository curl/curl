# These are all libcurl example programs to be test compiled
check_PROGRAMS = 10-at-a-time anyauthput cookie_interface debug fileupload \
  fopen ftpget ftpgetresp ftpupload getinfo getinmemory http-post httpput  \
  https multi-app multi-debugcallback multi-double multi-post multi-single \
  persistant post-callback postit2 sepheaders simple simplepost simplessl  \
  sendrecv httpcustomheader certinfo chkspeed ftpgetinfo ftp-wildcard \
  smtp-mail smtp-multi smtp-ssl smtp-tls smtp-vrfy smtp-expn rtsp \
  externalsocket resolve progressfunc pop3-retr pop3-list pop3-uidl pop3-dele \
  pop3-top pop3-stat pop3-noop pop3-ssl pop3-tls pop3-multi imap-list \
  imap-lsub imap-fetch imap-store imap-append imap-examine imap-search \
  imap-create imap-delete imap-copy imap-noop imap-ssl imap-tls imap-multi \
  url2file sftpget ftpsget postinmemory

# These examples require external dependencies that may not be commonly
# available on POSIX systems, so don't bother attempting to compile them here.
COMPLICATED_EXAMPLES = curlgtk.c curlx.c htmltitle.cpp cacertinmem.c	   \
  ftpuploadresume.c ghiper.c hiperfifo.c htmltidy.c multithread.c	   \
  opensslthreadlock.c sampleconv.c synctime.c threaded-ssl.c evhiperfifo.c \
  smooth-gtk-thread.c version-check.pl href_extractor.c asiohiper.cpp \
  multi-uv.c xmlstream.c usercertinmem.c sessioninfo.c
