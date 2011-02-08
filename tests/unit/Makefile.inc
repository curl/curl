# these files are used in every single unit test program

UNITFILES = curlcheck.h

# These are all unit test programs
noinst_PROGRAMS = unit1300 unit1301 unit1302 unit1303 unit1304

unit1300_SOURCES = unit1300.c $(UNITFILES)
unit1301_SOURCES = unit1301.c $(UNITFILES)
unit1302_SOURCES = unit1302.c $(UNITFILES)
unit1303_SOURCES = unit1303.c $(UNITFILES)
unit1304_SOURCES = unit1304.c $(UNITFILES)
