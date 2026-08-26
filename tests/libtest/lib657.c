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

/*
 * A CR or LF in a string option would let curl write an extra request line or
 * header onto the connection, so curl_easy_setopt() must reject it. Object and
 * callback-pointer options such as the POST body are not affected. The URL is
 * left for the URL parser to reject and credentials are checked per protocol
 * at transfer time instead (test 1910 verifies the HTTP case).
 */
static CURLcode test_lib657(const char *URL)
{
  const struct curl_easyoption *o;
  CURL *curl;
  int error = 0;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    return TEST_ERR_EASY_INIT;
  }

  /* every string option must refuse a value carrying a CR or LF */
  for(o = curl_easy_option_next(NULL); o; o = curl_easy_option_next(o)) {
    if(o->type == CURLOT_STRING) {
      CURLcode result;
      switch(o->id) {
      case CURLOPT_URL:           /* the URL parser rejects these bytes */
      case CURLOPT_USERPWD:       /* credentials are checked per protocol */
      case CURLOPT_USERNAME:
      case CURLOPT_PASSWORD:
      case CURLOPT_PROXYUSERPWD:
      case CURLOPT_PROXYUSERNAME:
      case CURLOPT_PROXYPASSWORD:
        continue;
      default:
        break;
      }
      result = curl_easy_setopt(curl, o->id, "curl\r\nInjected: 1");
      switch(result) {
      case CURLE_BAD_FUNCTION_ARGUMENT: /* rejected, as wanted */
      case CURLE_UNKNOWN_OPTION:        /* left out from the build */
      case CURLE_NOT_BUILT_IN:          /* not supported */
      case CURLE_UNSUPPORTED_PROTOCOL:  /* detected by protocol2num() */
        break;
      default:
        curl_mfprintf(stderr, "curl_easy_setopt(%s, CRLF) returned %d\n",
                      o->name, (int)result);
        error++;
        break;
      }
    }
  }

  /* a lone CR and a lone LF are both refused */
  if(curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET\rX") !=
     CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "CR in custom request not rejected\n");
    error++;
  }
  if(curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET\nX") !=
     CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "LF in custom request not rejected\n");
    error++;
  }

  /* a clean value is still accepted */
  if(curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET") != CURLE_OK) {
    curl_mfprintf(stderr, "clean custom request rejected\n");
    error++;
  }

  /* the POST body is not a string option and may carry a CR or LF */
  if(curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "a\r\nb") != CURLE_OK) {
    curl_mfprintf(stderr, "CRLF POST body rejected\n");
    error++;
  }

  /* credentials may carry these bytes at setopt time; protocols that cannot
     take them reject them when the transfer starts */
  if(curl_easy_setopt(curl, CURLOPT_USERPWD, "user\nname:pass\nword") !=
     CURLE_OK) {
    curl_mfprintf(stderr, "LF in credentials rejected at setopt\n");
    error++;
  }

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return error ? TEST_ERR_FAILURE : CURLE_OK;
}
