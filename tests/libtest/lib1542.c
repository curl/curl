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
 * Test CURLOPT_MAXLIFETIME_CONN:
 * Send four requests, sleeping between the second and third and setting
 * MAXLIFETIME_CONN between the third and fourth. The first three requests
 * should use the same connection, and the fourth request should close the
 * first connection and open a second.
 */

#include "first.h"

#include "testtrace.h"
#include "memdebug.h"

static CURLcode test_lib1542(char *URL)
{
  CURL *easy = NULL;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  res_easy_init(easy);

  easy_setopt(easy, CURLOPT_URL, URL);

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 0;
  easy_setopt(easy, CURLOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(easy, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(easy);
  if(res)
    goto test_cleanup;

  res = curl_easy_perform(easy);
  if(res)
    goto test_cleanup;

  /* CURLOPT_MAXLIFETIME_CONN is inclusive - the connection needs to be 2
   * seconds old */
  curlx_wait_ms(2000);

  res = curl_easy_perform(easy);
  if(res)
    goto test_cleanup;

  easy_setopt(easy, CURLOPT_MAXLIFETIME_CONN, 1L);

  res = curl_easy_perform(easy);
  if(res)
    goto test_cleanup;

test_cleanup:

  curl_easy_cleanup(easy);
  curl_global_cleanup();

  return res;
}
