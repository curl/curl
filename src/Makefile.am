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
# are also available at https://curl.se/docs/copyright.html.
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

# remove targets if the command fails
.DELETE_ON_ERROR:

EXTRA_DIST = mk-file-embed.pl mkhelp.pl \
 fetch.rc Makefile.inc CMakeLists.txt .checksrc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libfetch's external include files
# $(top_builddir)/lib is for libfetch's generated lib/fetch_config.h file
# $(top_builddir)/src is for fetch's generated src/fetch_config.h file
# $(top_srcdir)/lib for libfetch's lib/fetch_setup.h and other "borrowed" files
# $(top_srcdir)/src is for fetch's src/tool_setup.h and "fetch-private" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_builddir)/src          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/src

bin_PROGRAMS = fetch

if USE_CPPFLAG_FETCH_STATICLIB
AM_CPPFLAGS += -DFETCH_STATICLIB
endif
AM_CPPFLAGS += -DBUILDING_FETCH

AM_LDFLAGS =
if USE_UNICODE
AM_LDFLAGS += -municode
endif

include Makefile.inc

fetch_cfiles_gen =
fetch_hfiles_gen =
CLEANFILES =

if USE_UNITY
fetch_EXCLUDE =
if DEBUGBUILD
# We must compile this source separately to avoid memdebug.h redefinitions
# applying to them.
fetch_EXCLUDE += ../lib/fetch_multibyte.c
endif
if USE_CPPFLAG_FETCH_STATICLIB
fetch_FETCHX = $(FETCHTOOL_LIBFETCH_CFILES)
else
fetch_FETCHX = $(FETCHX_CFILES)
endif
fetchtool_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(FETCH_CFILES) $(fetch_cfiles_gen) $(fetch_FETCHX)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl $(srcdir) $(FETCH_CFILES) $(fetch_cfiles_gen) $(fetch_FETCHX) --exclude $(fetch_EXCLUDE) > fetchtool_unity.c

nodist_fetch_SOURCES = fetchtool_unity.c
fetch_SOURCES = $(fetch_EXCLUDE)
CLEANFILES += fetchtool_unity.c
else
# FETCH_FILES comes from Makefile.inc
fetch_SOURCES = $(FETCH_FILES) $(fetch_cfiles_gen) $(fetch_hfiles_gen)
endif
if HAVE_WINDRES
fetch_SOURCES += $(FETCH_RCFILES)
$(FETCH_RCFILES): tool_version.h
endif

fetch_LDFLAGS = $(AM_LDFLAGS) $(FETCH_LDFLAGS_BIN)

# This might hold -Werror
CFLAGS += @FETCH_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

fetch_LDADD = $(top_builddir)/lib/libfetch.la @LIBFETCH_PC_LIBS_PRIVATE@

# if unit tests are enabled, build a static library to link them with
if BUILD_UNITTESTS
noinst_LTLIBRARIES = libfetchtool.la
libfetchtool_la_CPPFLAGS = $(AM_CPPFLAGS) -DFETCH_STATICLIB -DUNITTESTS
libfetchtool_la_CFLAGS =
libfetchtool_la_LDFLAGS = -static $(LINKFLAGS)
if USE_UNITY
libfetchtool_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(FETCH_CFILES) $(FETCHTOOL_LIBFETCH_CFILES)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl $(srcdir) $(FETCH_CFILES) $(FETCHTOOL_LIBFETCH_CFILES) --exclude $(fetch_EXCLUDE) > libfetchtool_unity.c

nodist_libfetchtool_la_SOURCES = libfetchtool_unity.c
libfetchtool_la_SOURCES = $(fetch_EXCLUDE)
CLEANFILES += libfetchtool_unity.c
else
libfetchtool_la_SOURCES = $(FETCH_FILES)
endif
endif

# Use absolute directory to disable VPATH
ASCIIPAGE=$(top_builddir)/docs/cmdline-opts/fetch.txt
MKHELP=$(top_srcdir)/src/mkhelp.pl
HUGE=tool_hugehelp.c

HUGECMD = $(HUGEIT_$(V))
HUGEIT_0 = @echo "  HUGE    " $@;
HUGEIT_1 =
HUGEIT_ = $(HUGEIT_0)

fetch_CPPFLAGS = $(AM_CPPFLAGS)

if USE_MANUAL
# Here are the stuff to create a built-in manual
fetch_CPPFLAGS += -DUSE_MANUAL

$(ASCIIPAGE):
	cd $(top_builddir)/docs && $(MAKE)

if HAVE_LIBZ
# This generates the tool_hugehelp.c file in both uncompressed and
# compressed formats.
$(HUGE): $(ASCIIPAGE) $(MKHELP)
	$(HUGECMD) (echo '#include "tool_setup.h"' > $(HUGE);   \
	echo '#ifndef HAVE_LIBZ' >> $(HUGE);                    \
	$(PERL) $(MKHELP) < $(ASCIIPAGE) >> $(HUGE);     \
	echo '#else' >> $(HUGE);                                \
	$(PERL) $(MKHELP) -c < $(ASCIIPAGE) >> $(HUGE);  \
	echo '#endif /* HAVE_LIBZ */' >> $(HUGE) )
else # HAVE_LIBZ
# This generates the tool_hugehelp.c file uncompressed only
$(HUGE): $(ASCIIPAGE) $(MKHELP)
	$(HUGECMD)(echo '#include "tool_setup.h"' > $(HUGE);    \
	$(PERL) $(MKHELP) < $(ASCIIPAGE) >> $(HUGE) )
endif

else # USE_MANUAL
# built-in manual has been disabled, make a blank file
$(HUGE):
	echo '#include "tool_hugehelp.h"' >> $(HUGE)
endif

fetch_cfiles_gen += $(HUGE)
fetch_hfiles_gen += tool_hugehelp.h
CLEANFILES += $(HUGE)

CA_EMBED_CSOURCE = tool_ca_embed.c
fetch_cfiles_gen += $(CA_EMBED_CSOURCE)
CLEANFILES += $(CA_EMBED_CSOURCE)
if FETCH_CA_EMBED_SET
fetch_CPPFLAGS += -DFETCH_CA_EMBED
MK_FILE_EMBED = $(top_srcdir)/src/mk-file-embed.pl
$(CA_EMBED_CSOURCE): $(MK_FILE_EMBED) $(FETCH_CA_EMBED)
	$(PERL) $(MK_FILE_EMBED) --var fetch_ca_embed < $(FETCH_CA_EMBED) > $(CA_EMBED_CSOURCE)
else
$(CA_EMBED_CSOURCE):
	echo 'extern const void *fetch_ca_embed; const void *fetch_ca_embed;' > $(CA_EMBED_CSOURCE)
endif

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) \
	  -W$(srcdir)/$(HUGE) \
	  -W$(srcdir)/$(CA_EMBED_CSOURCE) \
	  -W$(srcdir)/fetchtool_unity.c \
	  -W$(srcdir)/libfetchtool_unity.c \
	  $(srcdir)/*.[ch])

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

tidy: $(HUGE) $(CA_EMBED_CSOURCE)
	$(TIDY) $(FETCH_CFILES) $(fetch_cfiles_gen) $(TIDYFLAGS) $(FETCH_CLANG_TIDYFLAGS) -- $(fetch_CPPFLAGS) $(CPPFLAGS) $(AM_CPPFLAGS) -DHAVE_CONFIG_H

listhelp:
	(cd $(top_srcdir)/docs/cmdline-opts && make listhelp)

if HAVE_WINDRES
.rc.o:
	$(RC) -I$(top_srcdir)/include -DFETCH_EMBED_MANIFEST $(RCFLAGS) -i $< -o $@
endif

dist-hook:
	rm -f $(distdir)/$(CA_EMBED_CSOURCE)
