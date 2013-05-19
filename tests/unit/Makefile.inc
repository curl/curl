# these files are used in every single unit test program

UNITFILES = curlcheck.h \
 ../libtest/test.h \
 ../libtest/first.c

# These are all unit test programs
UNITPROGS = unit1300 unit1301 unit1302 unit1303 unit1304 unit1305 unit1307 \
 unit1308 unit1309 unit1330 unit1394 unit1396

unit1300_SOURCES = unit1300.c $(UNITFILES)
unit1300_CPPFLAGS = $(AM_CPPFLAGS)

unit1301_SOURCES = unit1301.c $(UNITFILES)
unit1301_CPPFLAGS = $(AM_CPPFLAGS)

unit1302_SOURCES = unit1302.c $(UNITFILES)
unit1302_CPPFLAGS = $(AM_CPPFLAGS)

unit1303_SOURCES = unit1303.c $(UNITFILES)
unit1303_CPPFLAGS = $(AM_CPPFLAGS)

unit1304_SOURCES = unit1304.c $(UNITFILES)
unit1304_CPPFLAGS = $(AM_CPPFLAGS)

unit1305_SOURCES = unit1305.c $(UNITFILES)
unit1305_CPPFLAGS = $(AM_CPPFLAGS)

unit1307_SOURCES = unit1307.c $(UNITFILES)
unit1307_CPPFLAGS = $(AM_CPPFLAGS)

unit1308_SOURCES = unit1308.c $(UNITFILES)
unit1308_CPPFLAGS = $(AM_CPPFLAGS)

unit1309_SOURCES = unit1309.c $(UNITFILES)
unit1309_CPPFLAGS = $(AM_CPPFLAGS)

unit1330_SOURCES = unit1330.c $(UNITFILES)
unit1330_CPPFLAGS = $(AM_CPPFLAGS)

unit1394_SOURCES = unit1394.c $(UNITFILES)
unit1394_CPPFLAGS = $(AM_CPPFLAGS) $(LIBMETALINK_CPPFLAGS)
unit1394_LDADD = @LIBMETALINK_LIBS@ $(top_builddir)/lib/libcurl.la @LIBCURL_LIBS@
unit1394_LDFLAGS = @LIBMETALINK_LDFLAGS@ $(top_builddir)/src/libcurltool.la
unit1394_LIBS =

unit1396_SOURCES = unit1396.c $(UNITFILES)
unit1396_CPPFLAGS = $(AM_CPPFLAGS)
