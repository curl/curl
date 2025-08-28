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

# Get CURL_CFILES, CURL_HFILES, CURLX_CFILES, CURLX_HFILES, CURL_RCFILES variables
include Makefile.inc

EXTRA_DIST = CMakeLists.txt .checksrc mk-file-embed.pl mkhelp.pl $(CURL_RCFILES)

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files
# $(srcdir) for generated sources to find included sources

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(srcdir)

bin_PROGRAMS = curl

curlinfo_SOURCES = curlinfo.c
noinst_PROGRAMS = curlinfo

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
UNICODEFLAG = -municode
endif

curl_cfiles_gen =
curl_hfiles_gen =
CLEANFILES =

if USE_CPPFLAG_CURL_STATICLIB
curlx_csrc =
curlx_hsrc =
else
# These are part of the libcurl static lib. Add them here when linking shared.
curlx_csrc = $(CURLX_CFILES)
curlx_hsrc = $(CURLX_HFILES)
endif

if USE_UNITY
curltool_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(CURL_CFILES) $(curl_cfiles_gen) $(curlx_csrc)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl --include $(CURL_CFILES) $(curl_cfiles_gen) $(curlx_csrc) > curltool_unity.c

nodist_curl_SOURCES = curltool_unity.c
curl_SOURCES =
CLEANFILES += curltool_unity.c
else
curl_SOURCES = $(CURL_CFILES) $(CURL_HFILES) $(curl_cfiles_gen) $(curl_hfiles_gen) $(curlx_csrc) $(curlx_hsrc)
endif
if HAVE_WINDRES
curl_SOURCES += $(CURL_RCFILES)
$(CURL_RCFILES): tool_version.h
endif

curl_LDFLAGS = $(AM_LDFLAGS) $(CURL_LDFLAGS_BIN) $(UNICODEFLAG)

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
libcurltool_la_LDFLAGS = -static $(LIBCURL_PC_LIBS_PRIVATE)
if USE_UNITY
libcurltool_unity.c: $(top_srcdir)/scripts/mk-unity.pl $(CURL_CFILES) $(curlx_csrc)
	@PERL@ $(top_srcdir)/scripts/mk-unity.pl --include $(CURL_CFILES) $(curlx_csrc) > libcurltool_unity.c

nodist_libcurltool_la_SOURCES = libcurltool_unity.c
libcurltool_la_SOURCES =
CLEANFILES += libcurltool_unity.c
else
libcurltool_la_SOURCES = $(CURL_CFILES) $(CURL_HFILES) $(curlx_csrc) $(curlx_hsrc)
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

if PERL
if HAVE_LIBZ
# This generates the tool_hugehelp.c file in both uncompressed and
# compressed formats.
$(HUGE): $(ASCIIPAGE) $(MKHELP)
	$(HUGECMD)(                                                \
	echo '/* !checksrc! disable COPYRIGHT all */' > $(HUGE);   \
	echo '/* !checksrc! disable INCLUDEDUP all */' >> $(HUGE); \
	echo '/* !checksrc! disable LONGLINE all */' >> $(HUGE);   \
	echo '#include "tool_setup.h"' >> $(HUGE);                 \
	echo '#ifndef HAVE_LIBZ' >> $(HUGE);                       \
	@PERL@ $(MKHELP) < $(ASCIIPAGE) >> $(HUGE);                \
	echo '#else' >> $(HUGE);                                   \
	@PERL@ $(MKHELP) -c < $(ASCIIPAGE) >> $(HUGE);             \
	echo '#endif /* HAVE_LIBZ */' >> $(HUGE) )
else # HAVE_LIBZ
# This generates the tool_hugehelp.c file uncompressed only
$(HUGE): $(ASCIIPAGE) $(MKHELP)
	$(HUGECMD)(                                                \
	echo '/* !checksrc! disable COPYRIGHT all */' > $(HUGE);   \
	echo '#include "tool_setup.h"' >> $(HUGE);                 \
	@PERL@ $(MKHELP) < $(ASCIIPAGE) >> $(HUGE) )
endif
else # PERL
$(HUGE):
	$(HUGECMD)(                                                \
	if test ! -f "$(srcdir)/$(HUGE)"; then                     \
	  echo '/* !checksrc! disable COPYRIGHT all */' > $(HUGE); \
	  echo '#include "tool_hugehelp.h"' >> $(HUGE);            \
	  echo 'void hugehelp(void) {}' >> $(HUGE);                \
	  echo 'void showhelp(const char *trigger, const char *arg, const char *endarg)' >> $(HUGE); \
	  echo '{' >> $(HUGE);                                     \
	  echo '  (void)trigger; (void)arg; (void)endarg;' >> $(HUGE); \
	  echo '}' >> $(HUGE);                                     \
	fi)
endif

else # USE_MANUAL
# built-in manual has been disabled, make a blank file
$(HUGE):
	echo '/* !checksrc! disable COPYRIGHT all */' > $(HUGE);   \
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
	@PERL@ $(MK_FILE_EMBED) --var curl_ca_embed < $(CURL_CA_EMBED) > $(CA_EMBED_CSOURCE)
else
$(CA_EMBED_CSOURCE):
	echo '/* !checksrc! disable COPYRIGHT all */' > $(CA_EMBED_CSOURCE)
	echo 'extern const void *curl_ca_embed; const void *curl_ca_embed;' >> $(CA_EMBED_CSOURCE)
endif

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

# ignore generated C files since they play by slightly different rules!
checksrc:
	$(CHECKSRC)(@PERL@ $(top_srcdir)/scripts/checksrc.pl -D$(srcdir) $(CURL_CFILES) $(CURL_HFILES))

if NOT_CURL_CI
if DEBUGBUILD
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif
endif

# disable the tests that are mostly causing false positives
TIDYFLAGS := -checks=-clang-analyzer-security.insecureAPI.bzero,-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-optin.performance.Padding,-clang-analyzer-security.ArrayBound,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling -quiet
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
