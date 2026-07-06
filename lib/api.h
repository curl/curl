#ifndef HEADER_CURL_API_H
#define HEADER_CURL_API_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#define CURLEASY_MAGIC_NUMBER 0xc0dedbadU
#ifdef DEBUGBUILD
/* On a debug build, we want to fail hard on easy handles that
 * are not NULL, but no longer have the MAGIC touch. This gives
 * us early warning on things only discovered by valgrind otherwise. */
#define GOOD_EASY_HANDLE(x) \
  (((x) && ((x)->magic == CURLEASY_MAGIC_NUMBER)) ? TRUE : \
   (DEBUGASSERT(!(x)), FALSE))
#else
#define GOOD_EASY_HANDLE(x) \
  ((x) && ((x)->magic == CURLEASY_MAGIC_NUMBER))
#endif

#define CURLMULTI_MAGIC_NUMBER 0x000bab1e

#ifdef DEBUGBUILD
/* On a debug build, we want to fail hard on multi handles that
 * are not NULL, but no longer have the MAGIC touch. This gives
 * us early warning on things only discovered by valgrind otherwise. */
#define GOOD_MULTI_HANDLE(x)                         \
  (((x) && (x)->magic == CURLMULTI_MAGIC_NUMBER) ? TRUE : \
  (DEBUGASSERT(!(x)), FALSE))
#else
#define GOOD_MULTI_HANDLE(x) \
  ((x) && (x)->magic == CURLMULTI_MAGIC_NUMBER)
#endif

/* the API functions called on a CURL* */
typedef enum {
  CURL_EAPI_FN_easy_cleanup,
  CURL_EAPI_FN_easy_duphandle,
  CURL_EAPI_FN_easy_getinfo,
  CURL_EAPI_FN_easy_pause,
  CURL_EAPI_FN_easy_perform_ev,
  CURL_EAPI_FN_easy_perform,
  CURL_EAPI_FN_easy_recv,
  CURL_EAPI_FN_easy_reset,
  CURL_EAPI_FN_easy_send,
  CURL_EAPI_FN_easy_setopt,
  CURL_EAPI_FN_easy_ssls_export,
  CURL_EAPI_FN_easy_ssls_import,
  CURL_EAPI_FN_easy_upkeep,
  CURL_EAPI_FN_ws_recv,
  CURL_EAPI_FN_ws_send,
  CURL_EAPI_FN_ws_start_frame,
  CURL_EAPI_FN_LAST
} Curl_eapi_fn;

/* the API functions called on a CURLM* */
typedef enum {
  CURL_MAPI_FN_multi_add_handle,
  CURL_MAPI_FN_multi_assign,
  CURL_MAPI_FN_multi_cleanup,
  CURL_MAPI_FN_multi_fdset,
  CURL_MAPI_FN_multi_get_handles,
  CURL_MAPI_FN_multi_get_offt,
  CURL_MAPI_FN_multi_info_read,
  CURL_MAPI_FN_multi_notify_disable,
  CURL_MAPI_FN_multi_notify_enable,
  CURL_MAPI_FN_multi_perform,
  CURL_MAPI_FN_multi_poll,
  CURL_MAPI_FN_multi_remove_handle,
  CURL_MAPI_FN_multi_setopt,
  CURL_MAPI_FN_multi_socket_action,
  CURL_MAPI_FN_multi_socket_all,
  CURL_MAPI_FN_multi_socket,
  CURL_MAPI_FN_multi_timeout,
  CURL_MAPI_FN_multi_wait,
  CURL_MAPI_FN_multi_waitfds,
  CURL_MAPI_FN_LAST
} Curl_mapi_fn;

#define CURL_CBAPI_FN_START        (16 * 1024)

/* the callback functions */
typedef enum {
  CURL_CBAPI_FN_easy_chunk_bgn = CURL_CBAPI_FN_START,
  CURL_CBAPI_FN_easy_chunk_end,
  CURL_CBAPI_FN_easy_closesocket,
  CURL_CBAPI_FN_easy_cr_in_read,
  CURL_CBAPI_FN_easy_cr_in_resume_from,
  CURL_CBAPI_FN_easy_cw_out_cb,
  CURL_CBAPI_FN_easy_fdebug,
  CURL_CBAPI_FN_easy_fnmatch_data,
  CURL_CBAPI_FN_easy_fopensocket,
  CURL_CBAPI_FN_easy_fprereq,
  CURL_CBAPI_FN_easy_fprogress,
  CURL_CBAPI_FN_easy_fread_func,
  CURL_CBAPI_FN_easy_fsockopt,
  CURL_CBAPI_FN_easy_fsslctx,
  CURL_CBAPI_FN_easy_fwrite_rtp,
  CURL_CBAPI_FN_easy_fxferinfo,
  CURL_CBAPI_FN_easy_ioctl_func,
  CURL_CBAPI_FN_easy_resolver_start,
  CURL_CBAPI_FN_easy_seek_func,
  CURL_CBAPI_FN_easy_ssh_hostkeyfunc,
  CURL_CBAPI_FN_easy_ssh_keyfunc,
  CURL_CBAPI_FN_easy_trailer_callback,

  CURL_CBAPI_FN_multi_ntfy_cb,
  CURL_CBAPI_FN_multi_push_cb,
  CURL_CBAPI_FN_multi_socket_cb,
  CURL_CBAPI_FN_multi_timer_cb,

  CURL_CBAPI_FN_LAST
} Curl_cbapi_fn;


#define CURL_EAPI_MAX_RECURSION       7

struct Curl_eapi_stack {
  uint16_t count;
  uint16_t calls[CURL_EAPI_MAX_RECURSION];
};

struct Curl_eapi_guard {
  struct Curl_easy *data;  /* != NULL if handle stays */
  uint16_t depth;  /* > 0 if this guard was entered */
};

bool Curl_eapi_enter(struct Curl_eapi_guard *guard,
                     CURL *curl,
                     Curl_eapi_fn fn,
                     CURLcode *presult);
void Curl_eapi_leave(struct Curl_eapi_guard *guard);

/* Curl_eapi_enter() checks for curl being NULL, but windows compiler
 * analyzers do not realize this. *sigh* */
#define CURL_EAPI_ENTER(g, curl, fn, r) \
  Curl_eapi_enter((g), (curl), CURL_EAPI_FN_##fn, (r)) && (curl)
#define CURL_EAPI_LEAVE(g) \
  Curl_eapi_leave(g)


#define CURL_MAPI_MAX_RECURSION       15

struct Curl_mapi_stack {
  uint16_t count;
  uint16_t calls[CURL_MAPI_MAX_RECURSION];
};

struct Curl_mapi_guard {
  struct Curl_multi *multi;  /* != NULL if handle stays */
  uint16_t depth;  /* > 0 if this guard was entered */
};

bool Curl_mapi_enter(struct Curl_mapi_guard *guard,
                     CURLM *m,
                     Curl_mapi_fn fn,
                     CURLMcode *pmresult);
void Curl_mapi_leave(struct Curl_mapi_guard *guard);

/* Curl_mapi_enter() checks for m being NULL, but windows compiler
 * analyzers do not realize this. *sigh* */
#define CURL_MAPI_ENTER(g, m, fn, r) \
  Curl_mapi_enter((g), (m), CURL_MAPI_FN_##fn, (r)) && (m)
#define CURL_MAPI_LEAVE(g) \
  Curl_mapi_leave(g)


void Curl_cbapi_enter(struct Curl_mapi_guard *guard,
                      struct Curl_easy *data,
                      struct Curl_multi *multi,
                      Curl_cbapi_fn fn);
void Curl_cbapi_leave(struct Curl_mapi_guard *guard);

#define CURL_CBAPI_START(g, d, fn) \
  Curl_cbapi_enter((g), (d), NULL, CURL_CBAPI_FN_##fn)
#define CURL_CBAPI_MULTI_START(g, m, fn) \
  Curl_cbapi_enter((g), NULL, (m), CURL_CBAPI_FN_##fn)
#define CURL_CBAPI_END(g) \
  Curl_cbapi_leave(g)
#define CURL_CBAPI_MULTI_END(g) \
  Curl_cbapi_leave(g)


bool Curl_api_is_in_callback(struct Curl_easy *data);
bool Curl_api_multi_is_in_callback(struct Curl_multi *multi);

#endif /* HEADER_CURL_API_H */
