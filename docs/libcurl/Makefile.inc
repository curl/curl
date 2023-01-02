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

# Shared between Makefile.am and CMakeLists.txt

man_MANS = \
 curl_easy_cleanup.3 \
 curl_easy_duphandle.3 \
 curl_easy_escape.3 \
 curl_easy_getinfo.3 \
 curl_easy_header.3 \
 curl_easy_init.3 \
 curl_easy_nextheader.3 \
 curl_easy_option_by_id.3 \
 curl_easy_option_by_name.3 \
 curl_easy_option_next.3 \
 curl_easy_pause.3 \
 curl_easy_perform.3 \
 curl_easy_recv.3 \
 curl_easy_reset.3 \
 curl_easy_send.3 \
 curl_easy_setopt.3 \
 curl_easy_strerror.3 \
 curl_easy_unescape.3 \
 curl_easy_upkeep.3 \
 curl_escape.3 \
 curl_formadd.3 \
 curl_formfree.3 \
 curl_formget.3 \
 curl_free.3 \
 curl_getdate.3 \
 curl_getenv.3 \
 curl_global_cleanup.3 \
 curl_global_init.3 \
 curl_global_init_mem.3 \
 curl_global_sslset.3 \
 curl_mime_addpart.3 \
 curl_mime_data.3 \
 curl_mime_data_cb.3 \
 curl_mime_encoder.3 \
 curl_mime_filedata.3 \
 curl_mime_filename.3 \
 curl_mime_free.3 \
 curl_mime_headers.3 \
 curl_mime_init.3 \
 curl_mime_name.3 \
 curl_mime_subparts.3 \
 curl_mime_type.3 \
 curl_mprintf.3 \
 curl_multi_add_handle.3 \
 curl_multi_assign.3 \
 curl_multi_cleanup.3 \
 curl_multi_fdset.3 \
 curl_multi_info_read.3 \
 curl_multi_init.3 \
 curl_multi_perform.3 \
 curl_multi_poll.3 \
 curl_multi_remove_handle.3 \
 curl_multi_setopt.3 \
 curl_multi_socket.3 \
 curl_multi_socket_action.3 \
 curl_multi_socket_all.3 \
 curl_multi_strerror.3 \
 curl_multi_timeout.3 \
 curl_multi_wakeup.3 \
 curl_multi_wait.3 \
 curl_share_cleanup.3 \
 curl_share_init.3 \
 curl_share_setopt.3 \
 curl_share_strerror.3 \
 curl_slist_append.3 \
 curl_slist_free_all.3 \
 curl_strequal.3 \
 curl_strnequal.3 \
 curl_unescape.3 \
 curl_url.3 \
 curl_url_cleanup.3 \
 curl_url_dup.3 \
 curl_url_get.3 \
 curl_url_set.3 \
 curl_url_strerror.3 \
 curl_version.3 \
 curl_version_info.3 \
 curl_ws_meta.3 \
 curl_ws_recv.3 \
 curl_ws_send.3 \
 libcurl-easy.3 \
 libcurl-env.3 \
 libcurl-errors.3 \
 libcurl-multi.3 \
 libcurl-security.3 \
 libcurl-share.3 \
 libcurl-symbols.3 \
 libcurl-thread.3 \
 libcurl-tutorial.3 \
 libcurl-url.3 \
 libcurl.3
