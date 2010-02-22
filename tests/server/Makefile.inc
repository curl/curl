noinst_PROGRAMS = getpart resolve rtspd sockfilt sws tftpd

getpart_SOURCES = testpart.c \
 getpart.c \
 getpart.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/base64.h \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/warnless.c \
 $(top_srcdir)/lib/warnless.h
getpart_LDADD = @TEST_SERVER_LIBS@
getpart_CFLAGS = $(AM_CFLAGS)

resolve_SOURCES = resolve.c \
 getpart.c \
 getpart.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/base64.h \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/warnless.c \
 $(top_srcdir)/lib/warnless.h
resolve_LDADD = @TEST_SERVER_LIBS@
resolve_CFLAGS = $(AM_CFLAGS)

rtspd_SOURCES = rtspd.c \
 getpart.c \
 getpart.h \
 util.c \
 util.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/base64.h \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/strequal.c \
 $(top_srcdir)/lib/timeval.c \
 $(top_srcdir)/lib/warnless.c \
 $(top_srcdir)/lib/warnless.h
rtspd_LDADD = @TEST_SERVER_LIBS@
rtspd_CFLAGS = $(AM_CFLAGS)

sockfilt_SOURCES = sockfilt.c \
 getpart.c \
 getpart.h \
 util.c \
 util.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/base64.h \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/inet_pton.c \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/timeval.c \
 $(top_srcdir)/lib/warnless.c \
 $(top_srcdir)/lib/warnless.h
sockfilt_LDADD = @TEST_SERVER_LIBS@
sockfilt_CFLAGS = $(AM_CFLAGS)

sws_SOURCES = sws.c \
 getpart.c \
 getpart.h \
 util.c \
 util.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/base64.h \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/strequal.c \
 $(top_srcdir)/lib/timeval.c \
 $(top_srcdir)/lib/warnless.c \
 $(top_srcdir)/lib/warnless.h
sws_LDADD = @TEST_SERVER_LIBS@
sws_CFLAGS = $(AM_CFLAGS)

tftpd_SOURCES = tftpd.c tftp.h \
 getpart.c \
 getpart.h \
 util.c \
 util.h \
 $(top_srcdir)/lib/base64.c \
 $(top_srcdir)/lib/base64.h \
 $(top_srcdir)/lib/curlx.h \
 $(top_srcdir)/lib/memdebug.c \
 $(top_srcdir)/lib/memdebug.h \
 $(top_srcdir)/lib/mprintf.c \
 $(top_srcdir)/lib/timeval.c \
 $(top_srcdir)/lib/warnless.c \
 $(top_srcdir)/lib/warnless.h
tftpd_LDADD = @TEST_SERVER_LIBS@
tftpd_CFLAGS = $(AM_CFLAGS)
