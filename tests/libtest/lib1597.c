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

/* Testing CURLOPT_PROTOCOLS_STR */

#include "test.h"

#include "memdebug.h"

struct pair {
  const char *in;
  CURLcode *exp;
};

CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  curl_version_info_data *curlinfo;
  const char *const *proto;
  int n;
  int i;
  static CURLcode ok = CURLE_OK;
  static CURLcode bad = CURLE_BAD_FUNCTION_ARGUMENT;
  static CURLcode unsup = CURLE_UNSUPPORTED_PROTOCOL;
  static CURLcode httpcode = CURLE_UNSUPPORTED_PROTOCOL;
  static CURLcode httpscode = CURLE_UNSUPPORTED_PROTOCOL;
  static char protolist[1024];

  static const struct pair prots[] = {
    {"goobar", &unsup},
    {"http ", &unsup},
    {" http", &unsup},
    {"http", &httpcode},
    {"http,", &httpcode},
    {"https,", &httpscode},
    {"https,http", &httpscode},
    {"http,http", &httpcode},
    {"HTTP,HTTP", &httpcode},
    {",HTTP,HTTP", &httpcode},
    {"http,http,ft", &unsup},
    {"", &bad},
    {",,", &bad},
    {protolist, &ok},
    {"all", &ok},
    {NULL, NULL},
  };
  (void)URL;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  /* Get enabled protocols.*/
  curlinfo = curl_version_info(CURLVERSION_NOW);
  if(!curlinfo) {
    fputs("curl_version_info failed\n", stderr);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  n = 0;
  for(proto = curlinfo->protocols; *proto; proto++) {
    if((size_t) n >= sizeof(protolist)) {
      puts("protolist buffer too small\n");
      res = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    n += msnprintf(protolist + n, sizeof(protolist) - n, ",%s", *proto);
    if(curl_strequal(*proto, "http"))
      httpcode = CURLE_OK;
    if(curl_strequal(*proto, "https"))
      httpscode = CURLE_OK;
  }

  /* Run the tests. */
  for(i = 0; prots[i].in; i++) {
    res = curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, prots[i].in);
    if(res != *prots[i].exp) {
      printf("unexpectedly '%s' returned %d\n", prots[i].in, res);
      break;
    }
  }
  printf("Tested %u strings\n", i);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
