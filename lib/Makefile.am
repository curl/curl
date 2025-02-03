#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

CMAKE_DIST = CMakeLists.txt fetch_config.h.cmake

CHECKSRC_DIST = .checksrc vauth/.checksrc vquic/.checksrc vssh/.checksrc \
 vtls/.checksrc

EXTRA_DIST = config-mac.h config-os400.h config-plan9.h config-riscos.h \
 config-win32.h fetch_config.h.in libfetch.rc libfetch.def                 \
 $(CMAKE_DIST) Makefile.soname optiontable.pl $(CHECKSRC_DIST)

lib_LTLIBRARIES = libfetch.la

if BUILD_UNITTESTS
noinst_LTLIBRARIES = libfetchu.la
else
noinst_LTLIBRARIES =
endif

# This might hold -Werror
CFLAGS += @FETCH_CFLAG_EXTRAS@

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libfetch's external include files
# $(top_builddir)/lib is for libfetch's generated lib/fetch_config.h file
# $(top_srcdir)/lib for libfetch's lib/fetch_setup.h and other "private" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

include Makefile.soname

AM_CPPFLAGS += -DBUILDING_LIBFETCH
AM_LDFLAGS =
AM_CFLAGS =

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

if USE_UNITY
# Keep these separate to avoid duplicate definitions when linking libtests
# in static mode.
fetch_EXCLUDE = fetch_threads.c timediff.c warnless.c
if DEBUGBUILD
# We must compile these sources separately to avoid memdebug.h redefinitions
# applying to them.
fetch_EXCLUDE += memdebug.c fetch_multibyte.c
endif
libfetch_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(CSOURCES)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl $(srcdir) $(CSOURCES) --exclude $(fetch_EXCLUDE) > libfetch_unity.c

nodist_libfetch_la_SOURCES = libfetch_unity.c
libfetch_la_SOURCES = $(fetch_EXCLUDE)
nodist_libfetchu_la_SOURCES = libfetch_unity.c
libfetchu_la_SOURCES = $(fetch_EXCLUDE)
CLEANFILES = libfetch_unity.c
else
libfetch_la_SOURCES = $(CSOURCES) $(HHEADERS)
libfetchu_la_SOURCES = $(CSOURCES) $(HHEADERS)
endif

libfetch_la_CPPFLAGS_EXTRA =
libfetch_la_LDFLAGS_EXTRA =
libfetch_la_CFLAGS_EXTRA =

if FETCH_LT_SHLIB_USE_VERSION_INFO
libfetch_la_LDFLAGS_EXTRA += $(VERSIONINFO)
endif

if FETCH_LT_SHLIB_USE_NO_UNDEFINED
libfetch_la_LDFLAGS_EXTRA += -no-undefined
endif

if FETCH_LT_SHLIB_USE_MIMPURE_TEXT
libfetch_la_LDFLAGS_EXTRA += -mimpure-text
endif

if FETCH_LT_SHLIB_USE_VERSIONED_SYMBOLS
libfetch_la_LDFLAGS_EXTRA += -Wl,--version-script=libfetch.vers
else
# if symbol-hiding is enabled, hide them!
if DOING_FETCH_SYMBOL_HIDING
libfetch_la_LDFLAGS_EXTRA += -export-symbols-regex '^fetch_.*'
endif
endif

if USE_CPPFLAG_FETCH_STATICLIB
libfetch_la_CPPFLAGS_EXTRA += -DFETCH_STATICLIB
else
if HAVE_WINDRES
libfetch_la_SOURCES += $(LIB_RCFILES)
$(LIB_RCFILES): $(top_srcdir)/include/fetch/fetchver.h
endif
endif

if DOING_FETCH_SYMBOL_HIDING
libfetch_la_CPPFLAGS_EXTRA += -DFETCH_HIDDEN_SYMBOLS
libfetch_la_CFLAGS_EXTRA += $(CFLAG_FETCH_SYMBOL_HIDING)
endif

libfetch_la_CPPFLAGS = $(AM_CPPFLAGS) $(libfetch_la_CPPFLAGS_EXTRA)
libfetch_la_LDFLAGS = $(AM_LDFLAGS) $(libfetch_la_LDFLAGS_EXTRA) $(FETCH_LDFLAGS_LIB) $(LIBFETCH_PC_LIBS_PRIVATE)
libfetch_la_CFLAGS = $(AM_CFLAGS) $(libfetch_la_CFLAGS_EXTRA)

libfetchu_la_CPPFLAGS = $(AM_CPPFLAGS) -DFETCH_STATICLIB -DUNITTESTS
libfetchu_la_LDFLAGS = $(AM_LDFLAGS) -static $(LIBFETCH_PC_LIBS_PRIVATE)
libfetchu_la_CFLAGS = $(AM_CFLAGS)

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir)         \
	  -W$(srcdir)/libfetch_unity.c -W$(srcdir)/fetch_config.h $(srcdir)/*.[ch] \
	  $(srcdir)/vauth/*.[ch] $(srcdir)/vtls/*.[ch] $(srcdir)/vquic/*.[ch]    \
	  $(srcdir)/vssh/*.[ch])

if DEBUGBUILD
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif

# disable the tests that are mostly causing false positives
TIDYFLAGS := -checks=-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-optin.performance.Padding,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling -quiet
if FETCH_WERROR
TIDYFLAGS += --warnings-as-errors=*
endif

TIDY := clang-tidy

tidy:
	$(TIDY) $(CSOURCES) $(TIDYFLAGS) $(FETCH_CLANG_TIDYFLAGS) -- $(AM_CPPFLAGS) $(CPPFLAGS) -DHAVE_CONFIG_H

optiontable:
	perl optiontable.pl < $(top_srcdir)/include/fetch/fetch.h > easyoptions.c

if HAVE_WINDRES
.rc.lo:
	$(LIBTOOL) --tag=RC --mode=compile $(RC) -I$(top_srcdir)/include $(RCFLAGS) -i $< -o $@
endif
