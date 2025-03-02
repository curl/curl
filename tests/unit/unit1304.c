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
#include "curlcheck.h"
#include "netrc.h"
#include "memdebug.h" /* LAST include file */

#ifndef CURL_DISABLE_NETRC

static char *s_login;
static char *s_password;

static CURLcode unit_setup(void)
{
  s_password = NULL;
  s_login = NULL;
  return CURLE_OK;
}

static void unit_stop(void)
{
  Curl_safefree(s_password);
  Curl_safefree(s_login);
}

UNITTEST_START
{
  int result;
  struct store_netrc store;

  /*
   * Test a non existent host in our netrc file.
   */
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "test.example.com", &s_login, &s_password, arg);
  fail_unless(result == 1, "Host not found should return 1");
  abort_unless(s_password == NULL, "password did not return NULL!");
  abort_unless(s_login == NULL, "user did not return NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login in our netrc file.
   */
  s_login = (char *)CURL_UNCONST("me");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login and host in our netrc file.
   */
  s_login = (char *)CURL_UNCONST("me");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "test.example.com", &s_login, &s_password, arg);
  fail_unless(result == 1, "Host not found should return 1");
  abort_unless(s_password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (substring of an existing one) in our
   * netrc file.
   */
  s_login = (char *)CURL_UNCONST("admi");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (superstring of an existing one)
   * in our netrc file.
   */
  s_login = (char *)CURL_UNCONST("adminn");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file
   * with s_login[0] = 0.
   */
  s_login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password != NULL, "returned NULL!");
  fail_unless(strncmp(s_password, "passwd", 6) == 0,
              "password should be 'passwd'");
  abort_unless(s_login != NULL, "returned NULL!");
  fail_unless(strncmp(s_login, "admin", 5) == 0, "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file
   * with s_login[0] != 0.
   */
  free(s_password);
  free(s_login);
  s_password = NULL;
  s_login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password != NULL, "returned NULL!");
  fail_unless(strncmp(s_password, "passwd", 6) == 0,
              "password should be 'passwd'");
  abort_unless(s_login != NULL, "returned NULL!");
  fail_unless(strncmp(s_login, "admin", 5) == 0, "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file
   * with s_login[0] = 0.
   */
  free(s_password);
  s_password = NULL;
  free(s_login);
  s_login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "curl.example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password != NULL, "returned NULL!");
  fail_unless(strncmp(s_password, "none", 4) == 0,
              "password should be 'none'");
  abort_unless(s_login != NULL, "returned NULL!");
  fail_unless(strncmp(s_login, "none", 4) == 0, "login should be 'none'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file
   * with s_login[0] != 0.
   */
  free(s_password);
  free(s_login);
  s_password = NULL;
  s_login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "curl.example.com", &s_login, &s_password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(s_password != NULL, "returned NULL!");
  fail_unless(strncmp(s_password, "none", 4) == 0,
              "password should be 'none'");
  abort_unless(s_login != NULL, "returned NULL!");
  fail_unless(strncmp(s_login, "none", 4) == 0, "login should be 'none'");
  Curl_netrc_cleanup(&store);
}
UNITTEST_STOP

#else
static CURLcode unit_setup(void)
{
  return CURLE_OK;
}
static void unit_stop(void)
{
}
UNITTEST_START
UNITTEST_STOP

#endif
