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

EXTRA_DIST = coverage.sh completion.pl firefox-db2pem.sh checksrc.pl    \
 mk-ca-bundle.pl mk-unity.pl schemetable.c cd2nroff nroff2cd cdall cd2cd managen \
 dmaketgz maketgz release-tools.sh verify-release cmakelint.sh

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
if CROSSCOMPILING
	@echo "NOTICE: we can't generate zsh completion when cross-compiling!"
else # if not cross-compiling:
	if test -z "$(PERL)"; then echo "No perl: can't install completion script"; else \
	$(PERL) $(srcdir)/completion.pl --curl $(top_builddir)/src/curl$(EXEEXT) --shell zsh > $@ ; fi
endif
endif

if USE_FISH_COMPLETION
$(FISH_COMPLETION_FUNCTION_FILENAME): completion.pl
if CROSSCOMPILING
	@echo "NOTICE: we can't generate fish completion when cross-compiling!"
else # if not cross-compiling:
	if test -z "$(PERL)"; then echo "No perl: can't install completion script"; else \
	$(PERL) $(srcdir)/completion.pl --curl $(top_builddir)/src/curl$(EXEEXT) --shell fish > $@ ; fi
endif
endif

install-data-local:
if CROSSCOMPILING
	@echo "NOTICE: we can't install completion scripts when cross-compiling!"
else # if not cross-compiling:
if USE_ZSH_COMPLETION
	if test -n "$(PERL)"; then \
	  $(MKDIR_P) $(DESTDIR)$(ZSH_FUNCTIONS_DIR); \
	  $(INSTALL_DATA) $(ZSH_COMPLETION_FUNCTION_FILENAME) $(DESTDIR)$(ZSH_FUNCTIONS_DIR)/$(ZSH_COMPLETION_FUNCTION_FILENAME) ; \
	fi
endif
if USE_FISH_COMPLETION
	if test -n "$(PERL)"; then \
	  $(MKDIR_P) $(DESTDIR)$(FISH_FUNCTIONS_DIR); \
	  $(INSTALL_DATA) $(FISH_COMPLETION_FUNCTION_FILENAME) $(DESTDIR)$(FISH_FUNCTIONS_DIR)/$(FISH_COMPLETION_FUNCTION_FILENAME) ; \
	fi
endif
endif

distclean:
	rm -f $(CLEANFILES)
