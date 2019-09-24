# files used only in some libcurl test programs
TESTUTIL = testutil.c testutil.h

# files used only in some libcurl test programs
TSTTRACE = testtrace.c testtrace.h

# files used only in some libcurl test programs
WARNLESS = ../../lib/warnless.c ../../lib/warnless.h

# these files are used in every single test program below
SUPPORTFILES = first.c test.h

# These are all libcurl test programs
noinst_PROGRAMS = chkhostname libauthretry libntlmconnect

chkdecimalpoint_SOURCES = chkdecimalpoint.c ../../lib/mprintf.c \
 ../../lib/curl_ctype.c
chkdecimalpoint_LDADD =
chkdecimalpoint_CPPFLAGS = $(AM_CPPFLAGS) -DCURL_STATICLIB \
 -DCURLX_NO_MEMORY_CALLBACKS

chkhostname_SOURCES = chkhostname.c ../../lib/curl_gethostname.c
chkhostname_LDADD = @CURL_NETWORK_LIBS@
chkhostname_DEPENDENCIES =
chkhostname_CPPFLAGS = $(AM_CPPFLAGS)

libntlmconnect_SOURCES = libntlmconnect.c $(SUPPORTFILES) $(TESTUTIL) $(WARNLESS)
libntlmconnect_LDADD = $(TESTUTIL_LIBS)
libntlmconnect_CPPFLAGS = $(AM_CPPFLAGS)

libauthretry_SOURCES = libauthretry.c $(SUPPORTFILES)
libauthretry_CPPFLAGS = $(AM_CPPFLAGS)
