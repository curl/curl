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


#define CURL_API_COND_HANDLE_STAY     (1 << 0)
#define CURL_API_COND_NO_RECURSE      (1 << 1)
#define CURL_API_COND_NO_PAUSE        (1 << 2)

#define CURL_API_CHECK_PAUSE_OK       (1 << 0)
#define CURL_API_CHECK_NO_NOTIFY      (1 << 1)

struct Curl_api_eguard {
  struct Curl_easy *data;
  const struct Curl_api_eguard *prev;
#ifdef CURLVERBOSE
  const char *call;
#endif
  uint8_t condition;
  BIT(entered);
};

bool Curl_api_easy_enter(struct Curl_api_eguard *guard,
                         CURL *curl,
                         const char *call,
                         uint8_t condition,
                         CURLcode *presult);

void Curl_api_easy_leave(struct Curl_api_eguard *guard);

bool Curl_api_easy_check(struct Curl_api_eguard *guard,
                         uint8_t check,
                         CURLcode *presult);

#ifdef CURLVERBOSE
#define CURL_API_EASY_ENTER(g, curl, call, r) \
                            Curl_api_easy_enter((g), (curl), (call), \
                            (CURL_API_COND_NO_RECURSE | \
                             CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_EASY_REC_ENTER(g, curl, call, r) \
                            Curl_api_easy_enter((g), (curl), (call), \
                            (CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_EASY_CLEANUP(g, curl) \
                            Curl_api_easy_enter((g), (curl), \
                            "curl_easy_cleanup", \
                            (CURL_API_COND_NO_RECURSE), NULL)
#else
#define CURL_API_EASY_ENTER(g, curl, call, r) \
                            Curl_api_easy_enter((g), (curl), NULL,   \
                            (CURL_API_COND_NO_RECURSE | \
                             CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_EASY_REC_ENTER(g, curl, call, r) \
                            Curl_api_easy_enter((g), (curl), NULL, \
                            (CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_EASY_CLEANUP(g, curl) \
                            Curl_api_easy_enter((g), (curl), NULL, \
                            (CURL_API_COND_NO_RECURSE), NULL)
#endif

#define CURL_API_EASY_LEAVE(g)   Curl_api_easy_leave(g)

struct Curl_api_mguard {
  struct Curl_multi *multi;
  struct Curl_easy *data;
  const struct Curl_api_mguard *prev;
#ifdef CURLVERBOSE
  const char *call;
#endif
  uint8_t condition;
  BIT(entered);
  BIT(is_callback);
};

bool Curl_api_multi_enter(struct Curl_api_mguard *guard,
                          CURLM *m,
                          const char *call,
                          uint8_t condition,
                          CURLMcode *pmresult);

void Curl_api_multi_leave(struct Curl_api_mguard *guard);

bool Curl_api_multi_check(struct Curl_api_mguard *guard,
                         uint8_t check,
                         CURLMcode *pmresult);

#ifdef CURLVERBOSE
#define CURL_API_MULTI_ENTER(g, m, call, r) \
                            Curl_api_multi_enter((g), (m), (call), \
                            (CURL_API_COND_NO_RECURSE | \
                             CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_MULTI_REC_ENTER(g, m, call, r) \
                            Curl_api_multi_enter((g), (m), (call), \
                            (CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_MULTI_CLEANUP(g, m, r) \
                            Curl_api_multi_enter((g), (m), \
                            "curl_multi_cleanup", \
                            (CURL_API_COND_NO_RECURSE), (r))
#else
#define CURL_API_MULTI_ENTER(g, m, call, r) \
                            Curl_api_multi_enter((g), (m), NULL,   \
                            (CURL_API_COND_NO_RECURSE | \
                             CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_MULTI_REC_ENTER(g, m, call, r) \
                            Curl_api_multi_enter((g), (m), NULL,   \
                            (CURL_API_COND_HANDLE_STAY), (r))
#define CURL_API_MULTI_CLEANUP(g, m, r) \
                            Curl_api_multi_enter((g), (m), NULL, \
                            (CURL_API_COND_NO_RECURSE), (r))
#endif

#define CURL_API_MULTI_LEAVE(g)   Curl_api_multi_leave(g)

void Curl_api_multi_cb_enter(struct Curl_api_mguard *guard,
                             struct Curl_multi *multi,
                             const char *call,
                             uint8_t condition);
void Curl_api_multi_cb_leave(struct Curl_api_mguard *guard);
void Curl_api_easy_cb_enter(struct Curl_api_mguard *guard,
                            struct Curl_easy *data,
                            const char *call);
void Curl_api_easy_cb_leave(struct Curl_api_mguard *guard);

bool Curl_api_is_in_callback(struct Curl_easy *data);
bool Curl_api_multi_is_in_callback(struct Curl_multi *multi);

#ifdef CURLVERBOSE
#define CURL_API_CB_ENTER(g, d, call) \
                           Curl_api_easy_cb_enter((g), (d), (call))
#define CURL_API_MULTI_CB_ENTER(g, m, call, cond) \
                           Curl_api_multi_cb_enter((g), (m), (call), (cond))
#else
#define CURL_API_CB_ENTER(g, d, call) \
                           Curl_api_easy_cb_enter((g), (d), NULL)
#define CURL_API_MULTI_CB_ENTER(g, m, call, cond) \
                           Curl_api_multi_cb_enter((g), (m), NULL, (cond))
#endif
#define CURL_API_CB_LEAVE(g)          Curl_api_easy_cb_leave(g)
#define CURL_API_MULTI_CB_LEAVE(g)    Curl_api_multi_cb_leave(g)

#endif /* HEADER_CURL_API_H */
