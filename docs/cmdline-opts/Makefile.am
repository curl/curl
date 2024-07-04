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

AUTOMAKE_OPTIONS = foreign no-dependencies

MANPAGE = curl.1
ASCIIPAGE = curl.txt

include Makefile.inc

EXTRA_DIST = $(DPAGES) MANPAGE.md $(SUPPORT) CMakeLists.txt mainpage.idx

GEN = $(GN_$(V))
GN_0 = @echo "  GENERATE" $@;
GN_1 =
GN_ = $(GN_0)

MANAGEN=$(top_srcdir)/scripts/managen
INCDIR=$(top_srcdir)/include

if BUILD_DOCS
CLEANFILES = $(MANPAGE) $(ASCIIPAGE)
man_MANS = $(MANPAGE)

all: $(MANPAGE) $(ASCIIPAGE)

endif

$(MANPAGE): $(DPAGES) $(SUPPORT) mainpage.idx Makefile.inc $(MANAGEN)
	$(GEN)(rm -f $(MANPAGE) && @PERL@ $(MANAGEN) -d $(srcdir) -I $(INCDIR) mainpage $(DPAGES) > manpage.tmp.$$$$ && mv manpage.tmp.$$$$ $(MANPAGE))

$(ASCIIPAGE): $(DPAGES) $(SUPPORT) mainpage.idx Makefile.inc $(MANAGEN)
	$(GEN)(rm -f $(ASCIIPAGE) && @PERL@ $(MANAGEN) -d $(srcdir) -I $(INCDIR) ascii $(DPAGES) > asciipage.tmp.$$$$ && mv asciipage.tmp.$$$$ $(ASCIIPAGE))

listhelp:
	$(MANAGEN) -d $(srcdir) listhelp $(DPAGES) > $(top_builddir)/src/tool_listhelp.c

listcats:
	@$(MANAGEN) listcats $(DPAGES)
