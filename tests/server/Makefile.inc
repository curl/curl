noinst_PROGRAMS = getpart resolve rtspd sockfilt sws tftpd fake_ntlm

CURLX_SRCS = \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/nonblock.c \
 $(top_srcdir)/lib/strequal.c \
 $(top_srcdir)/lib/strtoofft.c \
 $(top_srcdir)/lib/timeval.c \
 $(top_srcdir)/lib/warnless.c

CURLX_HDRS = \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/curl_nonblock.h \
 $(top_srcdir)/lib/curl_strequal.h \
 $(top_srcdir)/lib/curl_strtoofft.h \
 $(top_srcdir)/lib/curl_timeval.h \
 $(top_srcdir)/lib/curl_warnless.h

USEFUL = \
 getpart.c \
 getpart.h \
 server_setup.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/curl_base64.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/curl_memdebug.h

UTIL = \
 util.c \
 util.h

getpart_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) \
 testpart.c
getpart_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
getpart_CFLAGS = $(AM_CFLAGS)

resolve_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 resolve.c
resolve_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
resolve_CFLAGS = $(AM_CFLAGS)

rtspd_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 rtspd.c
rtspd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
rtspd_CFLAGS = $(AM_CFLAGS)

sockfilt_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 sockfilt.c \
 $(top_srcdir)/lib/inet_pton.c
sockfilt_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
sockfilt_CFLAGS = $(AM_CFLAGS)

sws_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 sws.c \
 $(top_srcdir)/lib/inet_pton.c
sws_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
sws_CFLAGS = $(AM_CFLAGS)

tftpd_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 tftpd.c \
 server_tftp.h
tftpd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
tftpd_CFLAGS = $(AM_CFLAGS)

fake_ntlm_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 fake_ntlm.c
fake_ntlm_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
fake_ntlm_CFLAGS = $(AM_CFLAGS)
