/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* argv1 = URL
 * argv2 = main auth type
 * argv3 = second auth type
 */

#include "test.h"

#include "memdebug.h"

static int send_request(CURL *curl, const char *url, int seq, long auth_scheme, const char *userpwd)
{
  CURLcode res;
  char* full_url = malloc(strlen(url) + 4 + 1);
  if (!full_url) {
    fprintf(stderr, "Not enough memory for full url\n");
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  sprintf(full_url, "%s%04d", url, seq);
  fprintf(stderr, "Sending new request %d to %s with credential %s (auth %ld)\n", seq, full_url, userpwd, auth_scheme);
  test_setopt(curl, CURLOPT_URL, full_url);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_HTTPGET, 1L);
  test_setopt(curl, CURLOPT_USERPWD, userpwd);
  test_setopt(curl, CURLOPT_HTTPAUTH, auth_scheme);

  res = curl_easy_perform(curl);

test_cleanup:
  free(full_url); 
  return res;
}

static int send_wrong_password(CURL *curl, const char *url, int seq, long auth_scheme)
{
    return send_request(curl, url, seq, auth_scheme, "testuser:wrongpass");
}

static int send_right_password(CURL *curl, const char *url, int seq, long auth_scheme)
{
    return send_request(curl, url, seq, auth_scheme, "testuser:testpass");
}

static long parse_auth_name(const char *arg)
{
  if (!arg)
    return CURLAUTH_NONE;
  if (strcasecmp(arg, "basic") == 0)
    return CURLAUTH_BASIC;
  if (strcasecmp(arg, "digest") == 0)
    return CURLAUTH_DIGEST;
  if (strcasecmp(arg, "ntlm") == 0)
    return CURLAUTH_NTLM;
  return CURLAUTH_NONE;
}

int test(char *url)
{
  CURLcode res;
  CURL *curl = NULL;
  bool curl_is_init = FALSE;

  long main_auth_scheme = parse_auth_name(libtest_arg2);
  long fallback_auth_scheme = parse_auth_name(libtest_arg3);

  if (main_auth_scheme == CURLAUTH_NONE ||
   fallback_auth_scheme == CURLAUTH_NONE) {
    fprintf(stderr, "auth schemes not found on commandline\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  curl_is_init = TRUE;

  /* Send wrong password, then right password */

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  res = send_wrong_password(curl, url, 100, main_auth_scheme);
  if (res != CURLE_OK)
      goto test_cleanup;
  curl_easy_reset(curl);
  res = send_right_password(curl, url, 200, fallback_auth_scheme);
  if (res != CURLE_OK)
      goto test_cleanup;
  curl_easy_reset(curl);

  curl_easy_cleanup(curl);

  /* Send wrong password twice, then right password */

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  res = send_wrong_password(curl, url, 300, main_auth_scheme);
  if (res != CURLE_OK)
      goto test_cleanup;
  curl_easy_reset(curl);

  res = send_wrong_password(curl, url, 400, fallback_auth_scheme);
  if (res != CURLE_OK)
      goto test_cleanup;
  curl_easy_reset(curl);
  res = send_right_password(curl, url, 500, fallback_auth_scheme);
  if (res != CURLE_OK)
      goto test_cleanup;
  curl_easy_reset(curl);

test_cleanup:

  if (curl)
    curl_easy_cleanup(curl);
  if (curl_is_init)
    curl_global_cleanup();

  return (int)res;
}

