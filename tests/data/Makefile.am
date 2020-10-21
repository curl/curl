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
iall:
install:
test:

# TESTCASES are taken from Makefile.inc
include Makefile.inc

EXTRA_DIST = $(TESTCASES) DISABLED CMakeLists.txt

filecheck:
	@mkdir test-place; \
	cp "$(top_srcdir)"/tests/data/test[0-9]* test-place/; \
	rm test-place/*~; \
	for f in $(EXTRA_DIST); do \
	  if test -f "$(top_srcdir)/tests/data/$$f"; then \
	    rm -f "test-place/$$f"; \
	  else \
	    echo "$$f is listed but missing!"; \
	  fi \
	done; \
	echo "Local files not present in EXTRA_DIST:" ; \
	ls test-place; \
	! ls test-place | grep . >/dev/null ; \
	RC=$$? ; \
	rm -rf test-place ; \
	exit $$RC

show:
	@echo $(EXTRA_DIST)
