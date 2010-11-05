# ./src/Makefile.inc
# Using the backslash as line continuation character might be problematic
# with some make flavours, as Watcom's wmake showed us already. If we
# ever want to change this in a portable manner then we should consider
# this idea (posted to the libcurl list by Adam Kellas):
# CSRC1 = file1.c file2.c file3.c
# CSRC2 = file4.c file5.c file6.c
# CSOURCES = $(CSRC1) $(CSRC2)

# libcurl has sources that provide functions named curlx_* that aren't part of
# the official API, but we re-use the code here to avoid duplication.
CURLX_ONES = $(top_srcdir)/lib/strtoofft.c \
	$(top_srcdir)/lib/strdup.c \
	$(top_srcdir)/lib/rawstr.c \
	$(top_srcdir)/lib/nonblock.c

CURL_CFILES = main.c hugehelp.c urlglob.c writeout.c writeenv.c \
	getpass.c homedir.c curlutil.c os-specific.c xattr.c

CURL_HFILES = hugehelp.h setup.h config-win32.h config-mac.h \
	config-riscos.h urlglob.h version.h os-specific.h \
	writeout.h writeenv.h getpass.h homedir.h curlutil.h \
	xattr.h

curl_SOURCES = $(CURL_CFILES) $(CURLX_ONES) $(CURL_HFILES)

