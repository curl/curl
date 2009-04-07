noinst_PROGRAMS = sws getpart sockfilt resolve tftpd

useful = getpart.c getpart.h $(top_srcdir)/lib/strequal.c	\
 $(top_srcdir)/lib/base64.c $(top_srcdir)/lib/mprintf.c		\
 $(top_srcdir)/lib/memdebug.c $(top_srcdir)/lib/timeval.c

resolve_SOURCES= resolve.c util.c util.h $(useful)
resolve_LDADD = @TEST_SERVER_LIBS@

sws_SOURCES= sws.c util.c util.h $(useful)
sws_LDADD = @TEST_SERVER_LIBS@

sockfilt_SOURCES = sockfilt.c util.c util.h $(useful)	\
 $(top_srcdir)/lib/inet_pton.c
sockfilt_LDADD = @TEST_SERVER_LIBS@

getpart_SOURCES= testpart.c $(useful)
# This is needed because of (unused) network debugging functions in memdebug.c
getpart_LDADD = @TEST_SERVER_LIBS@

tftpd_SOURCES = tftpd.c util.c util.h $(useful) tftp.h
tftpd_LDADD = @TEST_SERVER_LIBS@
