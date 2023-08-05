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

EXTRA_DIST = updatemanpages.pl coverage.sh completion.pl firefox-db2pem.sh \
 checksrc.pl mk-ca-bundle.pl

ZSH_FUNCTIONS_DIR = @ZSH_FUNCTIONS_DIR@
FISH_FUNCTIONS_DIR = @FISH_FUNCTIONS_DIR@
PERL = @PERL@

ZSH_COMPLETION_FUNCTION_FILENAME = _curl
FISH_COMPLETION_FUNCTION_FILENAME = curl.fish

CLEANFILES = $(ZSH_COMPLETION_FUNCTION_FILENAME) $(FISH_COMPLETION_FUNCTION_FILENAME)

all-local: $(ZSH_COMPLETION_FUNCTION_FILENAME) $(FISH_COMPLETION_FUNCTION_FILENAME)

$(ZSH_COMPLETION_FUNCTION_FILENAME): completion.pl
if CROSSCOMPILING
	@echo "NOTICE: we can't generate zsh completion when cross-compiling!"
else # if not cross-compiling:
	@if ! test -x "$(PERL)"; then echo "No perl: can't install completion.pl"; exit 0; fi
	$(PERL) $(srcdir)/completion.pl --curl $(top_builddir)/src/curl$(EXEEXT) --shell zsh > $@
endif

$(FISH_COMPLETION_FUNCTION_FILENAME): completion.pl
if CROSSCOMPILING
	@echo "NOTICE: we can't generate fish completion when cross-compiling!"
else # if not cross-compiling:
	@if ! test -x "$(PERL)"; then echo "No perl: can't install completion.pl"; exit 0; fi
	$(PERL) $(srcdir)/completion.pl --curl $(top_builddir)/src/curl$(EXEEXT) --shell fish > $@
endif

install-data-local:
if CROSSCOMPILING
	@echo "NOTICE: we can't install zsh completion when cross-compiling!"
else # if not cross-compiling:
	$(MKDIR_P) $(DESTDIR)$(ZSH_FUNCTIONS_DIR)
	$(MKDIR_P) $(DESTDIR)$(FISH_FUNCTIONS_DIR)
	$(INSTALL_DATA) $(ZSH_COMPLETION_FUNCTION_FILENAME) $(DESTDIR)$(ZSH_FUNCTIONS_DIR)/$(ZSH_COMPLETION_FUNCTION_FILENAME)
	$(INSTALL_DATA) $(FISH_COMPLETION_FUNCTION_FILENAME) $(DESTDIR)$(FISH_FUNCTIONS_DIR)/$(FISH_COMPLETION_FUNCTION_FILENAME)
endif
