#
# $Id$
#

AUTOMAKE_OPTIONS = foreign no-dependencies

EXTRA_DIST = getdate.y \
       Makefile.b32 Makefile.b32.resp Makefile.m32 Makefile.vc6 \
       libcurl.def dllinit.c curllib.dsp curllib.dsw

lib_LTLIBRARIES = libcurl.la

INCLUDES = -I$(top_srcdir)/include


libcurl_la_LDFLAGS = -no-undefined -version-info 2:2:0
# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# If either revision or age are omitted, they default to 0. Also note that age
# must be less than or equal to the current interface number.
#
# Here are a set of rules to help you update your library version information: 
#
# 1.Start with version information of 0:0:0 for each libtool library.
#
# 2.Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
#
# 3.If the library source code has changed at all since the last update, then
# increment revision (c:r:a becomes c:r+1:a).
#
# 4.If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0.
#
# 5.If any interfaces have been added since the last public release, then
# increment age.
#
# 6.If any interfaces have been removed since the last public release, then
# set age to 0.
#

libcurl_la_SOURCES = \
arpa_telnet.h  file.c         getpass.h      netrc.h        timeval.c \
base64.c       file.h         hostip.c       progress.c     timeval.h \
base64.h       formdata.c     hostip.h       progress.h     \
cookie.c       formdata.h     http.c         sendf.c        \
cookie.h       ftp.c          http.h         sendf.h        url.c \
dict.c         ftp.h          if2ip.c        speedcheck.c   url.h \
dict.h         getdate.c      if2ip.h        speedcheck.h   urldata.h \
getdate.h      ldap.c         ssluse.c       version.c \
getenv.c       ldap.h         ssluse.h       \
escape.c       mprintf.c      telnet.c       \
escape.h       getpass.c      netrc.c        telnet.h       \
getinfo.c getinfo.h transfer.c strequal.c strequal.h easy.c \
security.h security.c krb4.c krb4.h memdebug.c memdebug.h inet_ntoa_r.h \
http_chunks.c http_chunks.h strtok.c strtok.h connect.c connect.h

noinst_HEADERS = setup.h transfer.h

# Say $(srcdir), so GNU make does not report an ambiguity with the .y.c rule.
$(srcdir)/getdate.c: getdate.y
	cd $(srcdir) && \
	  $(YACC) $(YFLAGS) getdate.y; \
	  mv -f y.tab.c getdate.c
