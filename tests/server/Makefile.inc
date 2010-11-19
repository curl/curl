noinst_PROGRAMS = getpart resolve rtspd sockfilt sws tftpd

CURLX_SRCS = \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/nonblock.c \
 $(top_srcdir)/lib/strequal.c \
 $(top_srcdir)/lib/strtoofft.c \
 $(top_srcdir)/lib/timeval.c \
 $(top_srcdir)/lib/warnless.c

CURLX_HDRS = \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/nonblock.h \
 $(top_srcdir)/lib/strequal.h \
 $(top_srcdir)/lib/strtoofft.h \
 $(top_srcdir)/lib/timeval.h \
 $(top_srcdir)/lib/warnless.h

USEFUL = \
 getpart.c \
 getpart.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/curl_base64.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h

UTIL = \
 util.c \
 util.h

getpart_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) \
 testpart.c
getpart_LDADD = @TEST_SERVER_LIBS@
getpart_CFLAGS = $(AM_CFLAGS)

resolve_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 resolve.c
resolve_LDADD = @TEST_SERVER_LIBS@
resolve_CFLAGS = $(AM_CFLAGS)

rtspd_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 rtspd.c
rtspd_LDADD = @TEST_SERVER_LIBS@
rtspd_CFLAGS = $(AM_CFLAGS)

sockfilt_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 sockfilt.c \
 $(top_srcdir)/lib/inet_pton.c
sockfilt_LDADD = @TEST_SERVER_LIBS@
sockfilt_CFLAGS = $(AM_CFLAGS)

sws_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 sws.c
sws_LDADD = @TEST_SERVER_LIBS@
sws_CFLAGS = $(AM_CFLAGS)

tftpd_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 tftpd.c \
 tftp.h
tftpd_LDADD = @TEST_SERVER_LIBS@
tftpd_CFLAGS = $(AM_CFLAGS)
