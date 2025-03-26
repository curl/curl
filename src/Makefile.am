#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
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
# SPDX-License-Identifier: curl
#
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

# remove targets if the command fails
.DELETE_ON_ERROR:

EXTRA_DIST = mk-file-embed.pl mkhelp.pl \
 curl.rc Makefile.inc CMakeLists.txt .checksrc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_builddir)/src is for curl's generated src/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files
# $(top_srcdir)/src is for curl's src/tool_setup.h and "curl-private" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_builddir)/src          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/src

bin_PROGRAMS = curl

if USE_CPPFLAG_CURL_STATICLIB
AM_CPPFLAGS += -DCURL_STATICLIB
endif
if DEBUGBUILD
AM_CPPFLAGS += -DDEBUGBUILD
endif
if CURLDEBUG
AM_CPPFLAGS += -DCURLDEBUG
endif

AM_LDFLAGS =
if USE_UNICODE
AM_LDFLAGS += -municode
endif

include Makefile.inc

curl_cfiles_gen =
curl_hfiles_gen =
CLEANFILES =

if USE_UNITY
curl_EXCLUDE =
if CURLDEBUG
# We must compile this source separately to avoid memdebug.h redefinitions
# applying to them.
curl_EXCLUDE += ../lib/curl_multibyte.c
endif
if USE_CPPFLAG_CURL_STATICLIB
curl_CURLX = $(CURLTOOL_LIBCURL_CFILES)
else
curl_CURLX = $(CURLX_CFILES)
endif
curltool_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(CURL_CFILES) $(curl_cfiles_gen) $(curl_CURLX)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl $(srcdir) $(CURL_CFILES) $(curl_cfiles_gen) $(curl_CURLX) --exclude $(curl_EXCLUDE) > curltool_unity.c

nodist_curl_SOURCES = curltool_unity.c
curl_SOURCES = $(curl_EXCLUDE)
CLEANFILES += curltool_unity.c
else
# CURL_FILES comes from Makefile.inc
curl_SOURCES = $(CURL_FILES) $(curl_cfiles_gen) $(curl_hfiles_gen)
endif
if HAVE_WINDRES
curl_SOURCES += $(CURL_RCFILES)
$(CURL_RCFILES): tool_version.h
endif

curl_LDFLAGS = $(AM_LDFLAGS) $(CURL_LDFLAGS_BIN)

# This might hold -Werror
CFLAGS += @CURL_CFLAG_EXTRAS@

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

curl_LDADD = $(top_builddir)/lib/libcurl.la @LIBCURL_PC_LIBS_PRIVATE@

# if unit tests are enabled, build a static library to link them with
if BUILD_UNITTESTS
noinst_LTLIBRARIES = libcurltool.la
libcurltool_la_CPPFLAGS = $(AM_CPPFLAGS) -DCURL_STATICLIB -DUNITTESTS
libcurltool_la_CFLAGS =
libcurltool_la_LDFLAGS = -static $(LINKFLAGS)
if USE_UNITY
libcurltool_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(CURL_CFILES) $(CURLTOOL_LIBCURL_CFILES)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl $(srcdir) $(CURL_CFILES) $(CURLTOOL_LIBCURL_CFILES) --exclude $(curl_EXCLUDE) > libcurltool_unity.c

nodist_libcurltool_la_SOURCES = libcurltool_unity.c
libcurltool_la_SOURCES = $(curl_EXCLUDE)
CLEANFILES += libcurltool_unity.c
else
libcurltool_la_SOURCES = $(CURL_FILES)
endif
endif

# Use absolute directory to disable VPATH
ASCIIPAGE=$(top_builddir)/docs/cmdline-opts/curl.txt
MKHELP=$(top_srcdir)/src/mkhelp.pl
HUGE=tool_hugehelp.c

HUGECMD = $(HUGEIT_$(V))
HUGEIT_0 = @echo "  HUGE    " $@;
HUGEIT_1 =
HUGEIT_ = $(HUGEIT_0)

curl_CPPFLAGS = $(AM_CPPFLAGS)

if USE_MANUAL
# Here are the stuff to create a built-in manual
curl_CPPFLAGS += -DUSE_MANUAL

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

curl_cfiles_gen += $(HUGE)
curl_hfiles_gen += tool_hugehelp.h
CLEANFILES += $(HUGE)

CA_EMBED_CSOURCE = tool_ca_embed.c
curl_cfiles_gen += $(CA_EMBED_CSOURCE)
CLEANFILES += $(CA_EMBED_CSOURCE)
if CURL_CA_EMBED_SET
curl_CPPFLAGS += -DCURL_CA_EMBED
MK_FILE_EMBED = $(top_srcdir)/src/mk-file-embed.pl
$(CA_EMBED_CSOURCE): $(MK_FILE_EMBED) $(CURL_CA_EMBED)
	$(PERL) $(MK_FILE_EMBED) --var curl_ca_embed < $(CURL_CA_EMBED) > $(CA_EMBED_CSOURCE)
else
$(CA_EMBED_CSOURCE):
	echo 'extern const void *curl_ca_embed; const void *curl_ca_embed;' > $(CA_EMBED_CSOURCE)
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
	  -W$(srcdir)/curltool_unity.c \
	  -W$(srcdir)/libcurltool_unity.c \
	  $(srcdir)/*.[ch])

if DEBUGBUILD
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif

# disable the tests that are mostly causing false positives
TIDYFLAGS := -checks=-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-optin.performance.Padding,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling -quiet
if CURL_WERROR
TIDYFLAGS += --warnings-as-errors=*
endif

TIDY := clang-tidy

tidy: $(HUGE) $(CA_EMBED_CSOURCE)
	(_curl_cfiles=`echo ' $(CURL_CFILES)' | sed -e 's/ +/ /g' -e 's| | $(srcdir)/|g'`; \
	$(TIDY) $$_curl_cfiles $(curl_cfiles_gen) $(TIDYFLAGS) $(CURL_CLANG_TIDYFLAGS) -- $(curl_CPPFLAGS) $(CPPFLAGS) $(AM_CPPFLAGS) -DHAVE_CONFIG_H)

listhelp:
	(cd $(top_srcdir)/docs/cmdline-opts && make listhelp)

if HAVE_WINDRES
.rc.o:
	$(RC) -I$(top_srcdir)/include $(RCFLAGS) -i $< -o $@
endif

dist-hook:
	rm -f $(distdir)/$(CA_EMBED_CSOURCE)
