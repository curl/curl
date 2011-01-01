# these files are used in every single unit test program

UNITFILES = curlcheck.h

# These are all unit test programs
noinst_PROGRAMS = unit1300

unit1300_SOURCES = unit1300.c $(UNITFILES)
