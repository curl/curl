#*************************************************************************** #
Project # _____ __ .__ # _/ ____\_____/ |_ ____ | |__ # \ __\/ __ \ __\/ ___\| |
\ # | | \ ___/| | \ \___| Y \ # |__| \___ >__| \___ >___| / # \/ \/ \/ # #
Copyright (C) Daniel Stenberg,
<daniel@haxx.se
  >, et al. # # This software is licensed as described in the file COPYING,
  which # you should have received as part of this distribution. The terms # are
  also available at https://curl.se/docs/copyright.html. # # You may opt to use,
  copy, modify, merge, publish, distribute and/or sell # copies of the Software,
  and permit persons to whom the Software is # furnished to do so, under the
  terms of the COPYING file. # # This software is distributed on an "AS IS"
  basis, WITHOUT WARRANTY OF ANY # KIND, either express or implied. # #
  SPDX-License-Identifier: fetch #
  ########################################################################### #
  Shared between Makefile.am and CMakeLists.txt man_MANS = \
  fetch_easy_cleanup.3 \ fetch_easy_duphandle.3 \ fetch_easy_escape.3 \
  fetch_easy_getinfo.3 \ fetch_easy_header.3 \ fetch_easy_init.3 \
  fetch_easy_nextheader.3 \ fetch_easy_option_by_id.3 \
  fetch_easy_option_by_name.3 \ fetch_easy_option_next.3 \ fetch_easy_pause.3 \
  fetch_easy_perform.3 \ fetch_easy_recv.3 \ fetch_easy_reset.3 \
  fetch_easy_send.3 \ fetch_easy_setopt.3 \ fetch_easy_ssls_export.3 \
  fetch_easy_ssls_import.3 \ fetch_easy_strerror.3 \ fetch_easy_unescape.3 \
  fetch_easy_upkeep.3 \ fetch_escape.3 \ fetch_formadd.3 \ fetch_formfree.3 \
  fetch_formget.3 \ fetch_free.3 \ fetch_getdate.3 \ fetch_getenv.3 \
  fetch_global_cleanup.3 \ fetch_global_init.3 \ fetch_global_init_mem.3 \
  fetch_global_sslset.3 \ fetch_global_trace.3 \ fetch_mime_addpart.3 \
  fetch_mime_data.3 \ fetch_mime_data_cb.3 \ fetch_mime_encoder.3 \
  fetch_mime_filedata.3 \ fetch_mime_filename.3 \ fetch_mime_free.3 \
  fetch_mime_headers.3 \ fetch_mime_init.3 \ fetch_mime_name.3 \
  fetch_mime_subparts.3 \ fetch_mime_type.3 \ fetch_mprintf.3 \
  fetch_multi_add_handle.3 \ fetch_multi_assign.3 \ fetch_multi_cleanup.3 \
  fetch_multi_fdset.3 \ fetch_multi_get_handles.3 \ fetch_multi_info_read.3 \
  fetch_multi_init.3 \ fetch_multi_perform.3 \ fetch_multi_poll.3 \
  fetch_multi_remove_handle.3 \ fetch_multi_setopt.3 \ fetch_multi_socket.3 \
  fetch_multi_socket_action.3 \ fetch_multi_socket_all.3 \
  fetch_multi_strerror.3 \ fetch_multi_timeout.3 \ fetch_multi_wait.3 \
  fetch_multi_waitfds.3 \ fetch_multi_wakeup.3 \ fetch_pushheader_byname.3 \
  fetch_pushheader_bynum.3 \ fetch_share_cleanup.3 \ fetch_share_init.3 \
  fetch_share_setopt.3 \ fetch_share_strerror.3 \ fetch_slist_append.3 \
  fetch_slist_free_all.3 \ fetch_strequal.3 \ fetch_strnequal.3 \
  fetch_unescape.3 \ fetch_url.3 \ fetch_url_cleanup.3 \ fetch_url_dup.3 \
  fetch_url_get.3 \ fetch_url_set.3 \ fetch_url_strerror.3 \ fetch_version.3 \
  fetch_version_info.3 \ fetch_ws_meta.3 \ fetch_ws_recv.3 \ fetch_ws_send.3 \
  libfetch-easy.3 \ libfetch-env-dbg.3 \ libfetch-env.3 \ libfetch-errors.3 \
  libfetch-multi.3 \ libfetch-security.3 \ libfetch-share.3 \ libfetch-symbols.3
  \ libfetch-thread.3 \ libfetch-tutorial.3 \ libfetch-url.3 \ libfetch-ws.3 \
  libfetch.3
</daniel@haxx.se>
