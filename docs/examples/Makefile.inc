# These are all libcurl example programs to be test compiled
check_PROGRAMS = 10-at-a-time anyauthput cookie_interface debug fileupload \
  fopen ftpget ftpgetresp ftpupload getinfo getinmemory http-post httpput  \
  https multi-app multi-debugcallback multi-double multi-post multi-single \
  persistant post-callback postit2 sepheaders simple simplepost simplessl  \
  sendrecv httpcustomheader certinfo chkspeed ftpgetinfo ftp-wildcard \
  smtp-multi simplesmtp smtp-tls rtsp externalsocket resolve \
  progressfunc pop3s pop3slist imap url2file sftpget ftpsget

# These examples require external dependencies that may not be commonly
# available on POSIX systems, so don't bother attempting to compile them here.
COMPLICATED_EXAMPLES = curlgtk.c curlx.c htmltitle.cpp cacertinmem.c	   \
  ftpuploadresume.c ghiper.c hiperfifo.c htmltidy.c multithread.c	   \
  opensslthreadlock.c sampleconv.c synctime.c threaded-ssl.c evhiperfifo.c \
  smooth-gtk-thread.c version-check.pl href_extractor.c asiohiper.cpp \
  multi-uv.c xmlstream.c usercertinmem.c
