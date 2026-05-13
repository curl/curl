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
#include "urldata.h"

static CURLcode test_unit3302(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  struct Curl_easy *easy;
  CURLcode result;

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy) {
    curl_global_cleanup();
    goto unit_test_abort; /* OOM during setup, not a test failure */
  }

  /* CURLGSSAPI_DELEGATION_FLAG must be stored */
  result = curl_easy_setopt(easy, CURLOPT_GSSAPI_DELEGATION,
                            CURLGSSAPI_DELEGATION_FLAG);
  fail_unless(result == CURLE_OK,
              "setopt DELEGATION_FLAG returned error");
  fail_unless(easy->set.gssapi_delegation == CURLGSSAPI_DELEGATION_FLAG,
              "DELEGATION_FLAG not stored in data->set");

  /* CURLGSSAPI_DELEGATION_POLICY_FLAG must be stored */
  result = curl_easy_setopt(easy, CURLOPT_GSSAPI_DELEGATION,
                            CURLGSSAPI_DELEGATION_POLICY_FLAG);
  fail_unless(result == CURLE_OK,
              "setopt DELEGATION_POLICY_FLAG returned error");
  fail_unless(easy->set.gssapi_delegation == CURLGSSAPI_DELEGATION_POLICY_FLAG,
              "DELEGATION_POLICY_FLAG not stored in data->set");

  /* both flags together */
  result = curl_easy_setopt(easy, CURLOPT_GSSAPI_DELEGATION,
                            CURLGSSAPI_DELEGATION_FLAG |
                            CURLGSSAPI_DELEGATION_POLICY_FLAG);
  fail_unless(result == CURLE_OK,
              "setopt both flags returned error");
  fail_unless(easy->set.gssapi_delegation ==
              (CURLGSSAPI_DELEGATION_FLAG | CURLGSSAPI_DELEGATION_POLICY_FLAG),
              "both delegation flags not stored in data->set");

  /* CURLGSSAPI_DELEGATION_NONE must clear the field */
  result = curl_easy_setopt(easy, CURLOPT_GSSAPI_DELEGATION,
                            CURLGSSAPI_DELEGATION_NONE);
  fail_unless(result == CURLE_OK,
              "setopt DELEGATION_NONE returned error");
  fail_unless(easy->set.gssapi_delegation == 0,
              "gssapi_delegation not cleared by DELEGATION_NONE");

  /* unknown bits must be masked off */
  result = curl_easy_setopt(easy, CURLOPT_GSSAPI_DELEGATION, 0xFFL);
  fail_unless(result == CURLE_OK,
              "setopt 0xFF returned error");
  fail_unless(easy->set.gssapi_delegation ==
              (CURLGSSAPI_DELEGATION_FLAG | CURLGSSAPI_DELEGATION_POLICY_FLAG),
              "unknown bits not masked off");

  curl_easy_cleanup(easy);
  curl_global_cleanup();
#endif /* HAVE_GSSAPI || USE_WINDOWS_SSPI */

  UNITTEST_END_SIMPLE
}
