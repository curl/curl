#
# $Id$
#

AUTOMAKE_OPTIONS = foreign no-dependencies

lib_LTLIBRARIES = libcurl.la
include_HEADERS = \
	$(top_srcdir)/include/curl/curl.h \
	$(top_srcdir)/include/curl/easy.h \
	$(top_srcdir)/include/curl/mprintf.h \
	$(top_srcdir)/include/curl/stdcheaders.h \
	$(top_srcdir)/include/curl/types.h

# Some flags needed when trying to cause warnings ;-)
# CFLAGS = -g -Wall #-pedantic

INCLUDES = -I$(top_srcdir)/include

libcurl_la_SOURCES = \
arpa_telnet.h  file.c         getpass.h      netrc.h        timeval.c \
base64.c       file.h         hostip.c       progress.c     timeval.h \
base64.h       formdata.c     hostip.h       progress.h     \
cookie.c       formdata.h     http.c         sendf.c        \
cookie.h       ftp.c          http.h         sendf.h        url.c \
dict.c         ftp.h          if2ip.c        speedcheck.c   url.h \
dict.h         getdate.c      if2ip.h        speedcheck.h   urldata.h \
download.c     getdate.h      ldap.c         ssluse.c       version.c \
download.h     getenv.c       ldap.h         ssluse.h       \
escape.c       getenv.h       mprintf.c      telnet.c       \
escape.h       getpass.c      netrc.c        telnet.h       \
writeout.c writeout.h highlevel.c strequal.c strequal.h easy.c

# Say $(srcdir), so GNU make does not report an ambiguity with the .y.c rule.
$(srcdir)/getdate.c: getdate.y
	cd $(srcdir) && \
	  $(YACC) $(YFLAGS) getdate.y; \
	  mv -f y.tab.c getdate.c
