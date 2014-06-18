#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
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
 curl_strequal.3 curl_mprintf.3 curl_global_init.3 curl_global_cleanup.3 \
 curl_multi_add_handle.3 curl_multi_cleanup.3 curl_multi_fdset.3	 \
 curl_multi_info_read.3 curl_multi_init.3 curl_multi_perform.3		 \
 curl_multi_remove_handle.3 curl_share_cleanup.3 curl_share_init.3	 \
 curl_share_setopt.3 libcurl.3 libcurl-easy.3 libcurl-multi.3		 \
 libcurl-share.3 libcurl-errors.3 curl_easy_strerror.3			 \
 curl_multi_strerror.3 curl_share_strerror.3 curl_global_init_mem.3	 \
 libcurl-tutorial.3 curl_easy_reset.3 curl_easy_escape.3		 \
 curl_easy_unescape.3 curl_multi_setopt.3 curl_multi_socket.3		 \
 curl_multi_timeout.3 curl_formget.3 curl_multi_assign.3		 \
 curl_easy_pause.3 curl_easy_recv.3 curl_easy_send.3			 \
 curl_multi_socket_action.3 curl_multi_wait.3

HTMLPAGES = curl_easy_cleanup.html curl_easy_getinfo.html		\
 curl_easy_init.html curl_easy_perform.html curl_easy_setopt.html	\
 curl_easy_duphandle.html curl_formadd.html curl_formfree.html		\
 curl_getdate.html curl_getenv.html curl_slist_append.html		\
 curl_slist_free_all.html curl_version.html curl_version_info.html	\
 curl_escape.html curl_unescape.html curl_free.html curl_strequal.html	\
 curl_mprintf.html curl_global_init.html curl_global_cleanup.html	\
 curl_multi_add_handle.html curl_multi_cleanup.html			\
 curl_multi_fdset.html curl_multi_info_read.html curl_multi_init.html	\
 curl_multi_perform.html curl_multi_remove_handle.html			\
 curl_share_cleanup.html curl_share_init.html curl_share_setopt.html	\
 libcurl.html libcurl-multi.html libcurl-easy.html libcurl-share.html	\
 libcurl-errors.html curl_easy_strerror.html curl_multi_strerror.html	\
 curl_share_strerror.html curl_global_init_mem.html			\
 libcurl-tutorial.html curl_easy_reset.html curl_easy_escape.html	\
 curl_easy_unescape.html curl_multi_setopt.html curl_multi_socket.html	\
 curl_multi_timeout.html curl_formget.html curl_multi_assign.html	\
 curl_easy_pause.html curl_easy_recv.html curl_easy_send.html		\
 curl_multi_socket_action.html curl_multi_wait.html

PDFPAGES = curl_easy_cleanup.pdf curl_easy_getinfo.pdf			 \
 curl_easy_init.pdf curl_easy_perform.pdf curl_easy_setopt.pdf		 \
 curl_easy_duphandle.pdf curl_formadd.pdf curl_formfree.pdf		 \
 curl_getdate.pdf curl_getenv.pdf curl_slist_append.pdf			 \
 curl_slist_free_all.pdf curl_version.pdf curl_version_info.pdf		 \
 curl_escape.pdf curl_unescape.pdf curl_free.pdf curl_strequal.pdf	 \
 curl_mprintf.pdf curl_global_init.pdf curl_global_cleanup.pdf		 \
 curl_multi_add_handle.pdf curl_multi_cleanup.pdf curl_multi_fdset.pdf	 \
 curl_multi_info_read.pdf curl_multi_init.pdf curl_multi_perform.pdf	 \
 curl_multi_remove_handle.pdf curl_share_cleanup.pdf curl_share_init.pdf \
 curl_share_setopt.pdf libcurl.pdf libcurl-multi.pdf libcurl-easy.pdf	 \
 libcurl-share.pdf libcurl-errors.pdf curl_easy_strerror.pdf		 \
 curl_multi_strerror.pdf curl_share_strerror.pdf			 \
 curl_global_init_mem.pdf libcurl-tutorial.pdf curl_easy_reset.pdf	 \
 curl_easy_escape.pdf curl_easy_unescape.pdf curl_multi_setopt.pdf	 \
 curl_multi_socket.pdf curl_multi_timeout.pdf curl_formget.pdf		 \
 curl_multi_assign.pdf curl_easy_pause.pdf curl_easy_recv.pdf		 \
 curl_easy_send.pdf curl_multi_socket_action.pdf curl_multi_wait.pdf

m4macrodir = $(datadir)/aclocal
dist_m4macro_DATA = libcurl.m4

CLEANFILES = $(HTMLPAGES) $(PDFPAGES)

EXTRA_DIST = $(man_MANS) $(HTMLPAGES) index.html $(PDFPAGES) ABI \
  symbols-in-versions symbols.pl
MAN2HTML= roffit --mandir=. < $< >$@

SUFFIXES = .3 .html

html: $(HTMLPAGES)
	cd opts; make html

.3.html:
	$(MAN2HTML)

pdf: $(PDFPAGES)
	cd opts; make pdf

.3.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")
