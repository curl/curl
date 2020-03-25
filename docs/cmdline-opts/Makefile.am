#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

AUTOMAKE_OPTIONS = foreign no-dependencies

MANPAGE = $(top_builddir)/docs/curl.1

include Makefile.inc

EXTRA_DIST = $(DPAGES) MANPAGE.md gen.pl $(OTHERPAGES) CMakeLists.txt

all: $(MANPAGE)

$(MANPAGE): $(DPAGES) $(OTHERPAGES) Makefile.inc
	@PERL@ $(srcdir)/gen.pl mainpage $(srcdir) > $(MANPAGE)

filecheck:
	@(INC="$(DPAGES)";                      \
	GIT=`git ls-files "*.d"`;               \
	for f in $$GIT; do                      \
	  found="no";                           \
	  for i in $$INC; do                    \
	    if test "$$f" = "$$i"; then         \
	      found="yes";                      \
	      break;			        \
	    fi                                  \
	  done;                                 \
          if test "$$found" != "yes"; then      \
	    echo "missing in DPAGES: $$f";	\
	    exit 1;			        \
	  fi				        \
	done)
