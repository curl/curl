/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "curlcheck.h"

#include "urldata.h"
#include "url.h"

#include "memdebug.h" /* LAST include file */

static CURLcode unit_setup(void)
{
  int res = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return res;
}

static void unit_stop(void)
{
  curl_global_cleanup();
}

UNITTEST_START
{
  int rc;
  struct Curl_easy *empty;
  const char *hostname = "hostname";
  enum dupstring i;

  bool async = FALSE;
  bool protocol_connect = FALSE;

  rc = Curl_open(&empty);
  if(rc)
    goto unit_test_abort;
  fail_unless(rc == CURLE_OK, "Curl_open() failed");

  rc = Curl_connect(empty, &async, &protocol_connect);
  fail_unless(rc == CURLE_URL_MALFORMAT,
              "Curl_connect() failed to return CURLE_URL_MALFORMAT");

  fail_unless(empty->magic == CURLEASY_MAGIC_NUMBER,
              "empty->magic should be equal to CURLEASY_MAGIC_NUMBER");

  /* double invoke to ensure no dependency on internal state */
  rc = Curl_connect(empty, &async, &protocol_connect);
  fail_unless(rc == CURLE_URL_MALFORMAT,
              "Curl_connect() failed to return CURLE_URL_MALFORMAT");

  rc = Curl_init_userdefined(empty);
  fail_unless(rc == CURLE_OK, "Curl_userdefined() failed");

  rc = Curl_init_do(empty, empty->conn);
  fail_unless(rc == CURLE_OK, "Curl_init_do() failed");

  rc = Curl_parse_login_details(
                          hostname, strlen(hostname), NULL, NULL, NULL);
  fail_unless(rc == CURLE_OK,
              "Curl_parse_login_details() failed");

  Curl_freeset(empty);
  for(i = (enum dupstring)0; i < STRING_LAST; i++) {
    fail_unless(empty->set.str[i] == NULL,
                "Curl_free() did not set to NULL");
  }

  Curl_free_request_state(empty);

  rc = Curl_close(&empty);
  fail_unless(rc == CURLE_OK, "Curl_close() failed");

}
UNITTEST_STOP
