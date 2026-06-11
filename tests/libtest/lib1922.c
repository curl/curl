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

static CURLcode test_lib1922(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  CURL *dup = NULL;
  struct curl_slist *resolve = NULL;
  char resolve_entry[256];
  char direct_url[256];
  char http_url[256];
  char proxy_url[256];
  const char *effective = NULL;
  const char *host = libtest_arg2;     /* %HOSTIP   */
  const char *httpport = libtest_arg3; /* %HTTPPORT  */
  const char *proxyport = libtest_arg4;/* %PROXYPORT */

  (void)URL;

  if(!host || !httpport || !proxyport) {
    curl_mfprintf(stderr,
                  "Usage: lib1922 - <host> <httpport> <proxyport>\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* Synthetic DNS so hsts.example.com resolves to the test server. */
  curl_msnprintf(resolve_entry, sizeof(resolve_entry),
                 "hsts.example.com:%s:%s", httpport, host);
  resolve = curl_slist_append(NULL, resolve_entry);
  if(!resolve) {
    return CURLE_OUT_OF_MEMORY;
  }

  curl_msnprintf(direct_url, sizeof(direct_url),
                 "http://hsts.example.com:%s/%d", httpport, 1922);
  curl_msnprintf(http_url, sizeof(http_url),
                 "http://hsts.example.com/%d", 1922);
  curl_msnprintf(proxy_url, sizeof(proxy_url),
                 "http://%s:%s", host, proxyport);

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_WRITEFUNCTION, tutil_throwaway_cb);
  easy_setopt(curl, CURLOPT_RESOLVE, resolve);
  easy_setopt(curl, CURLOPT_URL, direct_url);
  easy_setopt(curl, CURLOPT_HSTS_CTRL, CURLHSTS_ENABLE);

  /* Direct HTTP request: Server returns Strict-Transport-Security.
   * CURL_HSTS_HTTP env var (set in the test) allows processing it over
   * HTTP in debug builds, populating the live HSTS cache. */
  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr, "First perform failed: %d (%s)\n",
                  (int)result, curl_easy_strerror(result));
    goto test_cleanup;
  }
  curl_mprintf("First request: HSTS cache populated\n");

  dup = curl_easy_duphandle(curl);
  if(!dup) {
    result = CURLE_FAILED_INIT;
    goto test_cleanup;
  }

  /* Point the dup at the plain HTTP URL for the same hostname, via a proxy.
   * The copied HSTS cache upgrades the URL to HTTPS, causing a CONNECT to
   * port 443. The test proxy rejects CONNECT with 403, so curl returns
   * CURLE_COULDNT_CONNECT (7). The CONNECT to port 443 is itself the proof
   * of the upgrade. */
  easy_setopt(dup, CURLOPT_URL, http_url);
  easy_setopt(dup, CURLOPT_PROXY, proxy_url);

  result = curl_easy_perform(dup);
  if(result != CURLE_COULDNT_CONNECT) {
    curl_mfprintf(stderr, "Dup perform unexpected result: %d (%s)\n",
                  (int)result, curl_easy_strerror(result));
    goto test_cleanup;
  }

  /* Confirm the dup's URL was upgraded to HTTPS by the copied HSTS cache. */
  curl_easy_getinfo(dup, CURLINFO_EFFECTIVE_URL, &effective);
  if(effective) {
    curl_mprintf("Dup effective URL: %s\n", effective);
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_easy_cleanup(dup);
  curl_slist_free_all(resolve);
  curl_global_cleanup();
  return result;
}
