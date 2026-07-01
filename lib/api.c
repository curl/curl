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

#include "urldata.h"
#include "api.h"
#include "multiif.h"

bool Curl_api_easy_enter(struct Curl_api_eguard *guard,
                         CURL *curl,
                         const char *call,
                         uint8_t condition,
                         CURLcode *presult)
{
  guard->entered = FALSE;
  guard->data = curl;

  /* Verify that we got an easy handle we can work with. */
  if(!GOOD_EASY_HANDLE(guard->data)) {
    if(presult)
      *presult = CURLE_BAD_FUNCTION_ARGUMENT;
    return FALSE;
  }
  if((condition & CURL_API_COND_NO_RECURSE)) {
    if(Curl_api_is_in_callback(guard->data)) {
      if(presult)
        *presult = CURLE_RECURSIVE_API_CALL;
      return FALSE;
    }
    /* Calling with a curl_easy_*() call active? */
    if(guard->data->state.guard) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "API guard: calling %s with call to %s ongoing\n",
        call, guard->data->state.guard->call));
#endif
      if(presult)
        *presult = CURLE_RECURSIVE_API_CALL;
      return FALSE;
    }
    /* Calling with a curl_multi_*() call active?
     * notify callbacks are allowed to recurse */
    if(guard->data->multi && GOOD_MULTI_HANDLE(guard->data->multi) &&
       guard->data->multi->guard && !guard->data->multi->in_ntfy_callback) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "API guard: calling %s with call to %s ongoing\n",
        guard->call, guard->data->multi->guard->call));
#endif
      if(presult)
        *presult = CURLE_RECURSIVE_API_CALL;
      return FALSE;
    }
  }

  guard->condition = condition;
  guard->prev = guard->data->state.guard;
  guard->data->state.guard = guard;
#ifdef CURLVERBOSE
  guard->call = call;
#else
  (void)call;
#endif
  guard->entered = TRUE;
  if(presult)
    *presult = CURLE_OK;
  return TRUE;
}

void Curl_api_easy_leave(struct Curl_api_eguard *guard)
{
  if(guard->entered) {
    if((guard->condition & CURL_API_COND_HANDLE_STAY)) {
      if(GOOD_EASY_HANDLE(guard->data))
        guard->data->state.guard = guard->prev;
    }
    guard->data = NULL;
    guard->prev = NULL;
  }
}

bool Curl_api_multi_is_in_callback(struct Curl_multi *multi)
{
  if(multi) {
    /* Check the guard stack for callback guards */
    const struct Curl_api_mguard *stack = multi->guard;
    for(; stack; stack = stack->prev) {
      if(stack->is_callback)
        return TRUE;
    }
  }
  return FALSE;
}

bool Curl_api_is_in_callback(struct Curl_easy *data)
{
  if(data && data->multi) {
    return Curl_api_multi_is_in_callback(data->multi);
  }
  return FALSE;
}

bool Curl_api_easy_check(struct Curl_api_eguard *guard,
                         uint8_t check,
                         CURLcode *presult)
{
  if(check & CURL_API_CHECK_PAUSE_OK) {
    check = (uint8_t)(check & ~CURL_API_CHECK_PAUSE_OK);
    if(guard->data && guard->data->multi) {
      /* Check the guard stack for NO_PAUSE conditions */
      const struct Curl_api_mguard *stack = guard->data->multi->guard;
      for(; stack; stack = stack->prev) {
        if(stack->condition & CURL_API_COND_NO_PAUSE) {
          if(presult)
            *presult = CURLE_RECURSIVE_API_CALL;
          return FALSE;
        }
      }
    }
  }

  if(check) { /* unsupported check bits */
    DEBUGASSERT(0);
    if(presult)
      *presult = CURLE_BAD_FUNCTION_ARGUMENT;
    return FALSE;
  }
  if(presult)
    *presult = CURLE_OK;
  return TRUE;
}

bool Curl_api_multi_enter(struct Curl_api_mguard *guard,
                          CURLM *m,
                          const char *call,
                          uint8_t condition,
                          CURLMcode *pmresult)
{
  guard->entered = FALSE;
  guard->multi = m;

  /* Verify that we got an easy handle we can work with. */
  if(!GOOD_MULTI_HANDLE(guard->multi)) {
    if(pmresult)
      *pmresult = CURLM_BAD_FUNCTION_ARGUMENT;
    return FALSE;
  }
  if((condition & CURL_API_COND_NO_RECURSE)) {
    /* Calling with a curl_multi_*() call active?
     * notify callbacks are allowed to recurse */
    if(guard->multi->guard && !guard->multi->in_ntfy_callback) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "API guard: calling %s with call to %s ongoing\n",
        call, guard->multi->guard->call));
#endif
      if(pmresult)
        *pmresult = CURLM_RECURSIVE_API_CALL;
      return FALSE;
    }
  }

  guard->data = NULL;
  guard->condition = condition;
  guard->is_callback = FALSE;
  guard->prev = guard->multi->guard;
  guard->multi->guard = guard;
#ifdef CURLVERBOSE
  guard->call = call;
#else
  (void)call;
#endif
  guard->entered = TRUE;
  if(pmresult)
    *pmresult = CURLM_OK;
  return TRUE;
}

void Curl_api_multi_leave(struct Curl_api_mguard *guard)
{
  if(guard->entered) {
    if((guard->condition & CURL_API_COND_HANDLE_STAY)) {
      if(GOOD_MULTI_HANDLE(guard->multi))
        guard->multi->guard = guard->prev;
      if(guard->data && !GOOD_EASY_HANDLE(guard->data))
        DEBUGASSERT(0);
    }
    guard->multi = NULL;
    guard->data = NULL;
    guard->prev = NULL;
  }
}

bool Curl_api_multi_check(struct Curl_api_mguard *guard,
                         uint8_t check,
                         CURLMcode *pmresult)
{
  if(check & CURL_API_CHECK_NO_NOTIFY) {
    check = (uint8_t)(check & ~CURL_API_CHECK_NO_NOTIFY);
    if(guard->multi && guard->multi->in_ntfy_callback) {
      if(pmresult)
        *pmresult = CURLM_RECURSIVE_API_CALL;
      return FALSE;
    }
  }

  if(check) { /* unsupported check bits */
    DEBUGASSERT(0);
    if(pmresult)
      *pmresult = CURLM_BAD_FUNCTION_ARGUMENT;
    return FALSE;
  }
  if(pmresult)
    *pmresult = CURLM_OK;
  return TRUE;
}

void Curl_api_multi_cb_enter(struct Curl_api_mguard *guard,
                             struct Curl_multi *multi,
                             const char *call,
                             uint8_t condition)
{
  guard->entered = FALSE;
  guard->multi = multi;
  guard->data = NULL;
#ifdef CURLVERBOSE
  guard->call = call;
#else
  (void)call;
#endif
  guard->condition = condition | CURL_API_COND_HANDLE_STAY;
  guard->is_callback = TRUE;
  guard->prev = guard->multi->guard;
  guard->multi->guard = guard;
  guard->entered = TRUE;
}

void Curl_api_multi_cb_leave(struct Curl_api_mguard *guard)
{
  Curl_api_multi_leave(guard);
}

void Curl_api_easy_cb_enter(struct Curl_api_mguard *guard,
                            struct Curl_easy *data,
                            const char *call)
{
  guard->entered = FALSE;
  if(data->multi) {
    Curl_api_multi_cb_enter(guard, data->multi, call, 0);
    guard->data = data;
  }
}

void Curl_api_easy_cb_leave(struct Curl_api_mguard *guard)
{
  Curl_api_multi_leave(guard);
}

