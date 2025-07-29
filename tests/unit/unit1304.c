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
#include "netrc.h"
#include "memdebug.h" /* LAST include file */

#ifndef CURL_DISABLE_NETRC

static void t1304_stop(char **password, char **login)
{
  Curl_safefree(*password);
  Curl_safefree(*login);
}

static CURLcode test_unit1304(const char *arg)
{
  char *login = NULL;
  char *password = NULL;

  UNITTEST_BEGIN_SIMPLE

  int result;
  struct store_netrc store;

  /*
   * Test a non existent host in our netrc file.
   */
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "test.example.com", &login, &password, arg);
  fail_unless(result == 1, "Host not found should return 1");
  abort_unless(password == NULL, "password did not return NULL!");
  abort_unless(login == NULL, "user did not return NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login in our netrc file.
   */
  login = (char *)CURL_UNCONST("me");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login and host in our netrc file.
   */
  login = (char *)CURL_UNCONST("me");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "test.example.com", &login, &password, arg);
  fail_unless(result == 1, "Host not found should return 1");
  abort_unless(password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (substring of an existing one) in our
   * netrc file.
   */
  login = (char *)CURL_UNCONST("admi"); /* spellchecker:disable-line */
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test a non existent login (superstring of an existing one)
   * in our netrc file.
   */
  login = (char *)CURL_UNCONST("adminn");
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password == NULL, "password is not NULL!");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file
   * with login[0] = 0.
   */
  login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password != NULL, "returned NULL!");
  fail_unless(strncmp(password, "passwd", 6) == 0,
              "password should be 'passwd'");
  abort_unless(login != NULL, "returned NULL!");
  fail_unless(strncmp(login, "admin", 5) == 0, "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the first existing host in our netrc file
   * with login[0] != 0.
   */
  free(password);
  free(login);
  password = NULL;
  login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password != NULL, "returned NULL!");
  fail_unless(strncmp(password, "passwd", 6) == 0,
              "password should be 'passwd'");
  abort_unless(login != NULL, "returned NULL!");
  fail_unless(strncmp(login, "admin", 5) == 0, "login should be 'admin'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file
   * with login[0] = 0.
   */
  free(password);
  password = NULL;
  free(login);
  login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "curl.example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password != NULL, "returned NULL!");
  fail_unless(strncmp(password, "none", 4) == 0,
              "password should be 'none'");
  abort_unless(login != NULL, "returned NULL!");
  fail_unless(strncmp(login, "none", 4) == 0, "login should be 'none'");
  Curl_netrc_cleanup(&store);

  /*
   * Test for the second existing host in our netrc file
   * with login[0] != 0.
   */
  free(password);
  free(login);
  password = NULL;
  login = NULL;
  Curl_netrc_init(&store);
  result = Curl_parsenetrc(&store,
                           "curl.example.com", &login, &password, arg);
  fail_unless(result == 0, "Host should have been found");
  abort_unless(password != NULL, "returned NULL!");
  fail_unless(strncmp(password, "none", 4) == 0,
              "password should be 'none'");
  abort_unless(login != NULL, "returned NULL!");
  fail_unless(strncmp(login, "none", 4) == 0, "login should be 'none'");
  Curl_netrc_cleanup(&store);

  UNITTEST_END(t1304_stop(&password, &login))
}

#else

static CURLcode test_unit1304(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}

#endif
