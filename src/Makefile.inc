# ./src/Makefile.inc
 
# libcurl has sources that provide functions named curlx_* that aren't part of
# the official API, but we re-use the code here to avoid duplication.
CURLX_ONES =  $(top_srcdir)/lib/strtoofft.c $(top_srcdir)/lib/timeval.c

CURL_SOURCES = main.c hugehelp.c urlglob.c writeout.c writeenv.c \
	getpass.c homedir.c

CURL_HFILES = hugehelp.h setup.h config-win32.h config-mac.h \
	config-riscos.h urlglob.h version.h \
	writeout.h writeenv.h getpass.h homedir.h

curl_SOURCES = $(CURL_SOURCES) $(CURLX_ONES) $(CURL_HFILES)


