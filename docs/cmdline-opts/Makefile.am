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

MANPAGE = $(top_builddir)/docs/curl.1

include Makefile.inc

EXTRA_DIST = $(DPAGES) MANPAGE.md gen.pl $(OTHERPAGES) CMakeLists.txt

GEN = $(GN_$(V))
GN_0 = @echo "  GENERATE" $@;
GN_1 =
GN_ = $(GN_0)

all: $(MANPAGE)

$(MANPAGE): $(DPAGES) $(OTHERPAGES) Makefile.inc
	$(GEN)(rm -f $(MANPAGE) && cd $(srcdir) && @PERL@ ./gen.pl mainpage $(DPAGES) > $(builddir)/manpage.tmp && mv $(builddir)/manpage.tmp $(MANPAGE))
