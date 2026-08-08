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
#include "unitcheck.h"

/* All four strerror functions are public API, declared in curl/curl.h which
   is pulled in transitively through unitcheck.h -> curl_setup.h */

static CURLcode test_unit3406(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  const char *s;

  /* ==================================================================
   * curl_easy_strerror
   * In CURLVERBOSE builds each code maps to a unique, non-empty string.
   * In non-verbose builds CURLE_OK -> "No error", anything else -> "Error".
   * Both modes must return a non-NULL, non-empty string for every value.
   * ================================================================== */

  /* CURLE_OK always maps to a non-empty "success" string */
  s = curl_easy_strerror(CURLE_OK);
  abort_unless(s, "curl_easy_strerror(CURLE_OK) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(CURLE_OK) must not be empty");

  /* A handful of well-known error codes must return non-NULL/non-empty */
  s = curl_easy_strerror(CURLE_UNSUPPORTED_PROTOCOL);
  abort_unless(s, "curl_easy_strerror(CURLE_UNSUPPORTED_PROTOCOL) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(CURLE_UNSUPPORTED_PROTOCOL) not empty");

  s = curl_easy_strerror(CURLE_COULDNT_CONNECT);
  abort_unless(s, "curl_easy_strerror(CURLE_COULDNT_CONNECT) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(CURLE_COULDNT_CONNECT) not empty");

  s = curl_easy_strerror(CURLE_OUT_OF_MEMORY);
  abort_unless(s, "curl_easy_strerror(CURLE_OUT_OF_MEMORY) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(CURLE_OUT_OF_MEMORY) not empty");

  s = curl_easy_strerror(CURLE_OPERATION_TIMEDOUT);
  abort_unless(s, "curl_easy_strerror(CURLE_OPERATION_TIMEDOUT) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(CURLE_OPERATION_TIMEDOUT) not empty");

  s = curl_easy_strerror(CURLE_SSL_CONNECT_ERROR);
  abort_unless(s, "curl_easy_strerror(CURLE_SSL_CONNECT_ERROR) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(CURLE_SSL_CONNECT_ERROR) not empty");

  /* An out-of-range code must still return a non-NULL string, not crash */
  s = curl_easy_strerror((CURLcode)9999);
  abort_unless(s, "curl_easy_strerror(9999) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_easy_strerror(9999) must return a non-empty fallback");

  /* In CURLVERBOSE builds different codes must produce different strings */
#ifdef CURLVERBOSE
  {
    const char *s_ok  = curl_easy_strerror(CURLE_OK);
    const char *s_oom = curl_easy_strerror(CURLE_OUT_OF_MEMORY);
    fail_unless(strcmp(s_ok, s_oom) != 0,
                "distinct error codes must map to distinct strings");
  }
#endif

  /* ==================================================================
   * curl_multi_strerror
   * ================================================================== */

  s = curl_multi_strerror(CURLM_OK);
  abort_unless(s, "curl_multi_strerror(CURLM_OK) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_multi_strerror(CURLM_OK) must not be empty");

  s = curl_multi_strerror(CURLM_BAD_HANDLE);
  abort_unless(s, "curl_multi_strerror(CURLM_BAD_HANDLE) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_multi_strerror(CURLM_BAD_HANDLE) not empty");

  s = curl_multi_strerror(CURLM_OUT_OF_MEMORY);
  abort_unless(s, "curl_multi_strerror(CURLM_OUT_OF_MEMORY) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_multi_strerror(CURLM_OUT_OF_MEMORY) not empty");

  s = curl_multi_strerror(CURLM_INTERNAL_ERROR);
  abort_unless(s, "curl_multi_strerror(CURLM_INTERNAL_ERROR) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_multi_strerror(CURLM_INTERNAL_ERROR) not empty");

  /* Out-of-range must not crash */
  s = curl_multi_strerror((CURLMcode)9999);
  abort_unless(s, "curl_multi_strerror(9999) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_multi_strerror(9999) must return a non-empty fallback");

#ifdef CURLVERBOSE
  {
    const char *s_ok  = curl_multi_strerror(CURLM_OK);
    const char *s_bad = curl_multi_strerror(CURLM_BAD_HANDLE);
    fail_unless(strcmp(s_ok, s_bad) != 0,
                "CURLM_OK and CURLM_BAD_HANDLE must have distinct strings");
  }
#endif

  /* ==================================================================
   * curl_share_strerror
   * ================================================================== */

  s = curl_share_strerror(CURLSHE_OK);
  abort_unless(s, "curl_share_strerror(CURLSHE_OK) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_share_strerror(CURLSHE_OK) must not be empty");

  s = curl_share_strerror(CURLSHE_BAD_OPTION);
  abort_unless(s, "curl_share_strerror(CURLSHE_BAD_OPTION) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_share_strerror(CURLSHE_BAD_OPTION) not empty");

  s = curl_share_strerror(CURLSHE_IN_USE);
  abort_unless(s, "curl_share_strerror(CURLSHE_IN_USE) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_share_strerror(CURLSHE_IN_USE) not empty");

  s = curl_share_strerror(CURLSHE_INVALID);
  abort_unless(s, "curl_share_strerror(CURLSHE_INVALID) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_share_strerror(CURLSHE_INVALID) not empty");

  s = curl_share_strerror(CURLSHE_NOMEM);
  abort_unless(s, "curl_share_strerror(CURLSHE_NOMEM) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_share_strerror(CURLSHE_NOMEM) not empty");

  s = curl_share_strerror(CURLSHE_NOT_BUILT_IN);
  abort_unless(s, "curl_share_strerror(CURLSHE_NOT_BUILT_IN) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_share_strerror(CURLSHE_NOT_BUILT_IN) not empty");

#ifdef CURLVERBOSE
  {
    const char *s_ok  = curl_share_strerror(CURLSHE_OK);
    const char *s_err = curl_share_strerror(CURLSHE_IN_USE);
    fail_unless(strcmp(s_ok, s_err) != 0,
                "CURLSHE_OK and CURLSHE_IN_USE must have distinct strings");
  }
#endif

  /* ==================================================================
   * curl_url_strerror
   * ================================================================== */

  s = curl_url_strerror(CURLUE_OK);
  abort_unless(s, "curl_url_strerror(CURLUE_OK) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(CURLUE_OK) must not be empty");

  s = curl_url_strerror(CURLUE_BAD_HANDLE);
  abort_unless(s, "curl_url_strerror(CURLUE_BAD_HANDLE) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(CURLUE_BAD_HANDLE) not empty");

  s = curl_url_strerror(CURLUE_MALFORMED_INPUT);
  abort_unless(s, "curl_url_strerror(CURLUE_MALFORMED_INPUT) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(CURLUE_MALFORMED_INPUT) not empty");

  s = curl_url_strerror(CURLUE_NO_SCHEME);
  abort_unless(s, "curl_url_strerror(CURLUE_NO_SCHEME) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(CURLUE_NO_SCHEME) not empty");

  s = curl_url_strerror(CURLUE_NO_HOST);
  abort_unless(s, "curl_url_strerror(CURLUE_NO_HOST) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(CURLUE_NO_HOST) not empty");

  s = curl_url_strerror(CURLUE_BAD_IPV6);
  abort_unless(s, "curl_url_strerror(CURLUE_BAD_IPV6) != NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(CURLUE_BAD_IPV6) not empty");

  /* Out-of-range must not crash */
  s = curl_url_strerror((CURLUcode)9999);
  abort_unless(s, "curl_url_strerror(9999) must not return NULL");
  fail_unless(strlen(s) > 0,
              "curl_url_strerror(9999) must return a non-empty fallback");

#ifdef CURLVERBOSE
  {
    const char *s_ok  = curl_url_strerror(CURLUE_OK);
    const char *s_err = curl_url_strerror(CURLUE_NO_HOST);
    fail_unless(strcmp(s_ok, s_err) != 0,
                "CURLUE_OK and CURLUE_NO_HOST must have distinct strings");
  }
#endif

  UNITTEST_END_SIMPLE
}
