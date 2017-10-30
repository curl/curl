noinst_PROGRAMS = getpart resolve rtspd sockfilt sws tftpd fake_ntlm

CURLX_SRCS = \
 ../../lib/mprintf.c \
 ../../lib/nonblock.c \
 ../../lib/strtoofft.c \
 ../../lib/warnless.c

CURLX_HDRS = \
 ../../lib/curlx.h \
 ../../lib/nonblock.h \
 ../../lib/strtoofft.h \
 ../../lib/warnless.h

USEFUL = \
 getpart.c \
 getpart.h \
 server_setup.h \
 ../../lib/base64.c \
 ../../lib/curl_base64.h \
 ../../lib/memdebug.c \
 ../../lib/memdebug.h

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
 ../../lib/inet_pton.c
sockfilt_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
sockfilt_CFLAGS = $(AM_CFLAGS)

sws_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 sws.c \
 ../../lib/inet_pton.c
sws_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
sws_CFLAGS = $(AM_CFLAGS)

tftpd_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 server_sockaddr.h \
 tftpd.c \
 tftp.h
tftpd_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
tftpd_CFLAGS = $(AM_CFLAGS)

fake_ntlm_SOURCES = $(CURLX_SRCS) $(CURLX_HDRS) $(USEFUL) $(UTIL) \
 fake_ntlm.c
fake_ntlm_LDADD = @CURL_NETWORK_AND_TIME_LIBS@
fake_ntlm_CFLAGS = $(AM_CFLAGS)
