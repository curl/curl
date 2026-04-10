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

#include "first.h"

#ifdef USE_OPENSSL

#include <stdio.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <vtls/openssl.h>

#ifdef HAVE_BORINGSSL_LIKE
/* BoringSSL and AWS-LC */
typedef uint32_t opt1587;
#else
typedef uint64_t opt1587;
#endif

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  const struct curl_tlssessioninfo *info;
  CURLcode result;
  static int once;
  CURL *curl = stream;
  (void)ptr;

  if(!once++) {
    result = curl_easy_getinfo(curl, CURLINFO_TLS_SESSION, &info);

    if(result == CURLE_OK) {
      /* set and read stuff using the SSL_CTX to verify it */
      opt1587 opts = SSL_CTX_get_options(info->internals);
      SSL_CTX_set_options(info->internals, opts);
      curl_mprintf("CURLINFO_TLS_SESSION: OK\n");
    }

    result = curl_easy_getinfo(curl, CURLINFO_TLS_SSL_PTR, &info);

    if(result == CURLE_OK) {
      /* set and read stuff using the SSL pointer to verify it */
      opt1587 opts = SSL_get_options(info->internals);
      SSL_set_options(info->internals, opts);
      curl_mprintf("CURLINFO_TLS_SSL_PTR: OK\n");
    }
  }

  return size * nmemb;
}

static CURLcode test_lib1587(const char *URL)
{
  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl;
  if(result)
    return result;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return result;
}
#else
/* without OpenSSL this does nothing */
static CURLcode test_lib1587(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif
