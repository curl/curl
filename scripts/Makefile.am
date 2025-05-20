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

EXTRA_DIST = coverage.sh completion.pl firefox-db2pem.sh checksrc.pl checksrc-all.sh \
  mk-ca-bundle.pl mk-unity.pl schemetable.c cd2nroff nroff2cd cdall cd2cd managen    \
  dmaketgz maketgz release-tools.sh verify-release cmakelint.sh mdlinkcheck          \
  CMakeLists.txt pythonlint.sh randdisable wcurl top-complexity

dist_bin_SCRIPTS = wcurl

ZSH_FUNCTIONS_DIR = @ZSH_FUNCTIONS_DIR@
FISH_FUNCTIONS_DIR = @FISH_FUNCTIONS_DIR@
PERL = @PERL@

if USE_ZSH_COMPLETION
ZSH_COMPLETION_FUNCTION_FILENAME = _curl
endif
if USE_FISH_COMPLETION
FISH_COMPLETION_FUNCTION_FILENAME = curl.fish
endif

CLEANFILES = $(ZSH_COMPLETION_FUNCTION_FILENAME) $(FISH_COMPLETION_FUNCTION_FILENAME)

all-local: $(ZSH_COMPLETION_FUNCTION_FILENAME) $(FISH_COMPLETION_FUNCTION_FILENAME)

if USE_ZSH_COMPLETION
$(ZSH_COMPLETION_FUNCTION_FILENAME): completion.pl
	if test -z "$(PERL)"; then echo 'No perl: cannot generate completion script'; else \
	$(PERL) $(srcdir)/completion.pl --opts-dir $(top_srcdir)/docs/cmdline-opts --shell zsh > $@; fi
endif

if USE_FISH_COMPLETION
$(FISH_COMPLETION_FUNCTION_FILENAME): completion.pl
	if test -z "$(PERL)"; then echo 'No perl: cannot generate completion script'; else \
	$(PERL) $(srcdir)/completion.pl --opts-dir $(top_srcdir)/docs/cmdline-opts --shell fish > $@; fi
endif

install-data-local:
if USE_ZSH_COMPLETION
	if test -n "$(PERL)"; then \
	  $(MKDIR_P) $(DESTDIR)$(ZSH_FUNCTIONS_DIR); \
	  $(INSTALL_DATA) $(ZSH_COMPLETION_FUNCTION_FILENAME) $(DESTDIR)$(ZSH_FUNCTIONS_DIR)/$(ZSH_COMPLETION_FUNCTION_FILENAME); \
	fi
endif
if USE_FISH_COMPLETION
	if test -n "$(PERL)"; then \
	  $(MKDIR_P) $(DESTDIR)$(FISH_FUNCTIONS_DIR); \
	  $(INSTALL_DATA) $(FISH_COMPLETION_FUNCTION_FILENAME) $(DESTDIR)$(FISH_FUNCTIONS_DIR)/$(FISH_COMPLETION_FUNCTION_FILENAME); \
	fi
endif

distclean:
	rm -f $(CLEANFILES)
