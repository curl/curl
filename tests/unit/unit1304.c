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

static void t1304_stop(struct Curl_creds **pc1, struct Curl_creds **pc2)
{
  Curl_creds_unlink(pc1);
  Curl_creds_unlink(pc2);
}

static bool t1304_set_creds(const char *user, const char *passwd,
                           struct Curl_creds **pcreds)
{
  Curl_creds_unlink(pcreds);
  if(user || passwd)
    return !Curl_creds_create(user, passwd, NULL, NULL, CREDS_NONE, pcreds);
  else
    return TRUE;
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
  struct Curl_creds *cr_out = NULL, *cr_in = NULL;

  UNITTEST_BEGIN_SIMPLE

  int result;
  struct store_netrc store;

  /*
   * Test a non existent host in our netrc file.
   */
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "test.example.com", NULL, arg, &cr_out);
  fail_unless(result == 1, "expected no match");
  abort_unless(cr_out == NULL, "creds did not return NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login in our netrc file.
   */
  fail_unless(t1304_set_creds("me", NULL, &cr_in), "err set creds");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "example.com", cr_in, arg, &cr_out);
  fail_unless(result == 1, "expected no match");
  abort_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login and host in our netrc file.
   */
  fail_unless(t1304_set_creds("me", NULL, &cr_in), "err set creds");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "test.example.com", cr_in, arg, &cr_out);
  fail_unless(result == 1, "expected no match");
  abort_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (substring of an existing one) in our
   * netrc file.
   */
  fail_unless(t1304_set_creds(
    "admi", NULL, &cr_in), "err set creds"); /* spellchecker:disable-line */
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "example.com", cr_in, arg, &cr_out);
  fail_unless(result == 1, "expected no match");
  abort_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (superstring of an existing one)
   * in our netrc file.
   */
  fail_unless(t1304_set_creds("adminn", NULL, &cr_in), "err set creds");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "example.com", cr_in, arg, &cr_out);
  fail_unless(result == 1, "expected no match");
  abort_unless(t1304_no_passwd(cr_out), "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file
   * with login[0] = 0.
   */
  Curl_creds_unlink(&cr_in);
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "example.com", cr_in, arg, &cr_out);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(!t1304_no_passwd(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_passwd(cr_out), "passwd", 6) == 0,
              "password should be 'passwd'");
  abort_unless(!t1304_no_user(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_user(cr_out), "admin", 5) == 0,
              "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file
   * with login[0] != 0.
   */
  Curl_creds_unlink(&cr_in);
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "example.com", cr_in, arg, &cr_out);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(!t1304_no_passwd(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_passwd(cr_out), "passwd", 6) == 0,
              "password should be 'passwd'");
  abort_unless(!t1304_no_user(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_user(cr_out), "admin", 5) == 0,
              "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file
   * with login[0] = 0.
   */
  Curl_creds_unlink(&cr_in);
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "curl.example.com", cr_in, arg, &cr_out);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(!t1304_no_passwd(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_passwd(cr_out), "none", 4) == 0,
                      "password should be 'none'");
  abort_unless(!t1304_no_user(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_user(cr_out), "none", 4) == 0,
              "login should be 'none'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file
   * with login[0] != 0.
   */
  Curl_creds_unlink(&cr_in);
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store, "curl.example.com", cr_in, arg, &cr_out);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(!t1304_no_passwd(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_passwd(cr_out), "none", 4) == 0,
                      "password should be 'none'");
  abort_unless(!t1304_no_user(cr_out), "returned NULL!");
  fail_unless(strncmp(Curl_creds_user(cr_out), "none", 4) == 0,
                      "login should be 'none'");
  Curl_netrc_cleanup(&store);

  UNITTEST_END(t1304_stop(&cr_in, &cr_out))
}

#else

static CURLcode test_unit1304(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}

#endif
