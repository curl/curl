#
# $Id$
#

AUTOMAKE_OPTIONS = foreign no-dependencies

noinst_LIBRARIES = libcurl.a

# Some flags needed when trying to cause warnings ;-)
CFLAGS = -g #-Wall -pedantic

INCLUDES = -I$(top_srcdir)/include

libcurl_a_SOURCES = \
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
writeout.c writeout.h

# Say $(srcdir), so GNU make does not report an ambiguity with the .y.c rule.
$(srcdir)/getdate.c: getdate.y
	cd $(srcdir) && \
	  $(YACC) $(YFLAGS) getdate.y; \
	  mv -f y.tab.c getdate.c
