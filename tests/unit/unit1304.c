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

#ifndef CURL_DISABLE_NETRC
#include "netrc.h"
#include "creds.h"

static CURLcode t1304_setup(struct Curl_easy **easy)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return result;
}

static void t1304_stop(struct Curl_easy *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static bool t1304_no_user(struct Curl_creds *creds)
{
  return !creds || !creds->user[0];
}

static bool t1304_no_passwd(struct Curl_creds *creds)
{
  return !creds || !creds->passwd[0];
}

static CURLcode test_unit1304(const char *arg)
{
  struct Curl_creds *cr_out = NULL;
  struct Curl_easy *data;
  NETRCcode res;
  struct store_netrc store;

  UNITTEST_BEGIN(t1304_setup(&data))

  /*
   * Test a non existent host in our netrc file.
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(data, &store, "test.example.com", NULL, arg, &cr_out);
  fail_unless(res == NETRC_NO_MATCH, "expected no match");
  fail_unless(!cr_out, "creds did not return NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login in our netrc file.
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(data, &store, "example.com", "me", arg, &cr_out);
  fail_unless(res == NETRC_NO_MATCH, "expected no match");
  fail_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login and host in our netrc file.
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(data, &store, "test.example.com", "me", arg, &cr_out);
  fail_unless(res == NETRC_NO_MATCH, "expected no match");
  fail_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (substring of an existing one) in our
   * netrc file.
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(data, &store, "example.com", "a", arg, &cr_out);
  fail_unless(res == NETRC_NO_MATCH, "expected no match");
  fail_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (superstring of an existing one)
   * in our netrc file.
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(
    data, &store, "example.com", "administrator", arg, &cr_out);
  fail_unless(res == NETRC_NO_MATCH, "expected no match");
  fail_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file with no user
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(data, &store, "example.com", NULL, arg, &cr_out);
  fail_unless(res == NETRC_OK, "Host should have been found");
  fail_unless(!strncmp(Curl_creds_passwd(cr_out), "passwd", 6),
              "password should be 'passwd'");
  fail_unless(!t1304_no_user(cr_out), "returned NULL!");
  fail_unless(!strncmp(Curl_creds_user(cr_out), "admin", 5),
              "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file with no user
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(data, &store, "curl.example.com", NULL, arg, &cr_out);
  fail_unless(res == NETRC_OK, "Host should have been found");
  fail_unless(!strncmp(Curl_creds_passwd(cr_out), "none", 4),
                      "password should be 'none'");
  fail_unless(!t1304_no_user(cr_out), "returned NULL!");
  fail_unless(!strncmp(Curl_creds_user(cr_out), "none", 4),
              "login should be 'none'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the last host where we do not want to see the password
   * if the login does not match.
   */
  Curl_netrc_init(&store);
  res = Curl_netrc_scan(
    data, &store, "curl.example.com", "hilarious", arg, &cr_out);
  fail_unless(res == NETRC_NO_MATCH, "expect no match");
  fail_unless(!Curl_creds_has_passwd(cr_out), "password must be NULL");
  Curl_netrc_cleanup(&store);

  Curl_creds_unlink(&cr_out);

  UNITTEST_END(t1304_stop(data))
}

#else

static CURLcode test_unit1304(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}

#endif
