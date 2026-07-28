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

/*
 * OpenSSL-only mTLS test: HTTPS GET using a client certificate and private
 * key against an mTLS server. Invocation:
 *   <URL> <ca-cert> <client-cert> <client-key>
 */

#include "first.h"

#ifdef USE_OPENSSL

static CURLcode test_lib2099(const char *URL)
{
  CURL *curl;
  CURLcode result = TEST_ERR_MAJOR_BAD;

  if(!libtest_arg2 || !libtest_arg3 || !libtest_arg4) {
    curl_mfprintf(stderr, "lib2099: missing args\n");
    return CURLE_OBSOLETE20;
  }

  if(curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL) != CURLSSLSET_OK) {
    curl_mfprintf(stderr, "lib2099: could not select OpenSSL backend\n");
    return CURLE_OBSOLETE20;
  }

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_CAINFO, libtest_arg2);  /* CA cert */
  easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PROV"); /* client cert type */
  easy_setopt(curl, CURLOPT_SSLCERT, libtest_arg3); /* client cert */
  easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PROV"); /* private key type */
  easy_setopt(curl, CURLOPT_SSLKEY, libtest_arg4);  /* private key */

  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                  __FILE__, __LINE__, (int)result,
                  curl_easy_strerror(result));
    goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}

#else

static CURLcode test_lib2099(const char *URL)
{
  (void)URL;
  curl_mfprintf(stderr, "lib2099: requires OpenSSL\n");
  return CURLE_OK;
}

#endif
