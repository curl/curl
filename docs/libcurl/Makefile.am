#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

SUBDIRS = opts

man_MANS = curl_easy_cleanup.3 curl_easy_getinfo.3 curl_easy_init.3	 \
 curl_easy_perform.3 curl_easy_setopt.3 curl_easy_duphandle.3		 \
 curl_formadd.3 curl_formfree.3 curl_getdate.3 curl_getenv.3		 \
 curl_slist_append.3 curl_slist_free_all.3 curl_version.3		 \
 curl_version_info.3 curl_escape.3 curl_unescape.3 curl_free.3		 \
 curl_strequal.3 curl_mprintf.3 curl_global_init.3			 \
 curl_global_cleanup.3 curl_multi_add_handle.3 curl_multi_cleanup.3	 \
 curl_multi_fdset.3 curl_multi_info_read.3 curl_multi_init.3		 \
 curl_multi_perform.3 curl_multi_remove_handle.3 curl_share_cleanup.3	 \
 curl_share_init.3 curl_share_setopt.3 libcurl.3 libcurl-easy.3 	 \
 libcurl-multi.3 libcurl-share.3 libcurl-errors.3 curl_easy_strerror.3	 \
 curl_multi_strerror.3 curl_share_strerror.3 curl_global_init_mem.3	 \
 libcurl-tutorial.3 curl_easy_reset.3 curl_easy_escape.3		 \
 curl_easy_unescape.3 curl_multi_setopt.3 curl_multi_socket.3		 \
 curl_multi_timeout.3 curl_formget.3 curl_multi_assign.3		 \
 curl_easy_pause.3 curl_easy_recv.3 curl_easy_send.3			 \
 curl_multi_socket_action.3 curl_multi_wait.3 libcurl-symbols.3 	 \
 libcurl-thread.3 curl_multi_socket_all.3

HTMLPAGES = $(man_MANS:.3=.html)

PDFPAGES = $(man_MANS:.3=.pdf)

m4macrodir = $(datadir)/aclocal
dist_m4macro_DATA = libcurl.m4

CLEANFILES = $(HTMLPAGES) $(PDFPAGES) $(TESTS) libcurl-symbols.3

EXTRA_DIST = $(man_MANS) index.html ABI symbols-in-versions symbols.pl  \
  mksymbolsmanpage.pl
MAN2HTML= roffit --mandir=. $< >$@

SUFFIXES = .3 .html

libcurl-symbols.3: $(srcdir)/symbols-in-versions $(srcdir)/mksymbolsmanpage.pl
	perl $(srcdir)/mksymbolsmanpage.pl < $(srcdir)/symbols-in-versions > $@

html: $(HTMLPAGES)
	cd opts && make html

.3.html:
	$(MAN2HTML)

pdf: $(PDFPAGES)
	cd opts && make pdf

.3.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

# Make sure each option man page is referenced in the main man page
TESTS = check-easy check-multi
LOG_COMPILER = $(PERL)
# The test fails if the log file contains any text
AM_LOG_FLAGS = -p -e 'die "$$_" if ($$_);'

check-easy: $(srcdir)/curl_easy_setopt.3 $(srcdir)/opts/CURLOPT*.3
	OPTS="$$(ls $(srcdir)/opts/CURLOPT*.3 | $(SED) -e 's,^.*/,,' -e 's,\.3$$,,')" && \
	for opt in $$OPTS; do grep "^\.IP $$opt$$" $(srcdir)/curl_easy_setopt.3 >/dev/null || echo Missing $$opt; done > $@

check-multi: $(srcdir)/curl_multi_setopt.3 $(srcdir)/opts/CURLMOPT*.3
	OPTS="$$(ls $(srcdir)/opts/CURLMOPT*.3 | $(SED) -e 's,^.*/,,' -e 's,\.3$$,,')" && \
	for opt in $$OPTS; do grep "^\.IP $$opt$$" $(srcdir)/curl_multi_setopt.3 >/dev/null || echo Missing $$opt; done > $@
