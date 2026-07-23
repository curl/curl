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
#include "testtrace.h"

static CURLcode test_lib2017(const char *URL)
{
  CURLcode result;
  CURL *curl;
  int errors = 0;

  struct curl_slist crlist = {
    CURL_UNCONST("data and a \x0d in there"), NULL
  };
  struct curl_slist lflist = {
    CURL_UNCONST("data and a \x0a in there"), NULL
  };
  struct curl_slist bothlist[] = {
    { CURL_UNCONST("nothing harmful"), NULL },
    { CURL_UNCONST("both a \x0a and a \0x0d embedded"), NULL}
  };

  /* all slist options should reject these lists */
  int opts[] = {
    CURLOPT_PROXYHEADER,
    CURLOPT_HTTP200ALIASES,
    CURLOPT_POSTQUOTE,
    CURLOPT_PREQUOTE,
    CURLOPT_QUOTE,
    CURLOPT_RESOLVE,
    CURLOPT_HTTPHEADER,
    CURLOPT_TELNETOPTIONS,
    CURLOPT_MAIL_RCPT,
    CURLOPT_CONNECT_TO,
    -1 /* end of list */
  };

  int i;

  bothlist[0].next = &bothlist[1];

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  easy_setopt(curl, CURLOPT_URL, URL);

  for(i = 0; opts[i] != -1; i++) {
    CURLcode result1;
    CURLcode result2;
    CURLcode result3;
    int o = opts[i];
    result1 = curl_easy_setopt(curl, o, &lflist);
    if(!result1)
      curl_mfprintf(stderr, "Option %d unepectedly OK for LF", o);

    result2 = curl_easy_setopt(curl, opts[i], &crlist);
    if(!result2)
      curl_mfprintf(stderr, "Option %d unepectedly OK for CR", o);

    result3 = curl_easy_setopt(curl, opts[i], &bothlist);
    if(!result3)
      curl_mfprintf(stderr, "Option %d unepectedly OK for CR+LF", o);

    if(!result1 || !result2 || !result3)
      errors++;
  }

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return errors ? CURLE_BAD_FUNCTION_ARGUMENT : CURLE_OK;
}
