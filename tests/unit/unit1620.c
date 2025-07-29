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
#include "url.h"

#include "memdebug.h" /* LAST include file */

static CURLcode t1620_setup(void)
{
  CURLcode res = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return res;
}

static void t1620_parse(
  const char *input,
  const char *exp_username,
  const char *exp_password,
  const char *exp_options)
{
  char *userstr = NULL;
  char *passwdstr = NULL;
  char *options = NULL;
  CURLcode rc = Curl_parse_login_details(input, strlen(input),
                                &userstr, &passwdstr, &options);
  fail_unless(rc == CURLE_OK, "Curl_parse_login_details() failed");

  fail_unless(!!exp_username == !!userstr, "username expectation failed");
  fail_unless(!!exp_password == !!passwdstr, "password expectation failed");
  fail_unless(!!exp_options == !!options, "options expectation failed");

  if(!unitfail) {
    fail_unless(!userstr || !exp_username ||
                strcmp(userstr, exp_username) == 0,
                "userstr should be equal to exp_username");
    fail_unless(!passwdstr || !exp_password ||
                strcmp(passwdstr, exp_password) == 0,
                "passwdstr should be equal to exp_password");
    fail_unless(!options || !exp_options ||
                strcmp(options, exp_options) == 0,
                "options should be equal to exp_options");
  }

  free(userstr);
  free(passwdstr);
  free(options);
}

static CURLcode test_unit1620(const char *arg)
{
  UNITTEST_BEGIN(t1620_setup())

  CURLcode rc;
  struct Curl_easy *empty;
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

  t1620_parse("hostname", "hostname", NULL, NULL);
  t1620_parse("user:password", "user", "password", NULL);
  t1620_parse("user:password;options", "user", "password", "options");
  t1620_parse("user:password;options;more", "user", "password",
              "options;more");
  t1620_parse("", "", NULL, NULL);
  t1620_parse(":", "", "", NULL);
  t1620_parse(":;", "", "", NULL);
  t1620_parse(":password", "", "password", NULL);
  t1620_parse(":password;", "", "password", NULL);
  t1620_parse(";options", "", NULL, "options");
  t1620_parse("user;options", "user", NULL, "options");
  t1620_parse("user:;options", "user", "", "options");
  t1620_parse("user;options:password", "user", "password", "options");
  t1620_parse("user;options:", "user", "", "options");

  Curl_freeset(empty);
  for(i = (enum dupstring)0; i < STRING_LAST; i++) {
    fail_unless(empty->set.str[i] == NULL,
                "Curl_free() did not set to NULL");
  }

  rc = Curl_close(&empty);
  fail_unless(rc == CURLE_OK, "Curl_close() failed");

  UNITTEST_END(curl_global_cleanup())
}
