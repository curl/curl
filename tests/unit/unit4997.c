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
#include "cookie.h"

#ifndef CURL_DISABLE_COOKIES
static bool t4997_fail;
static bool t4997_injected;

static void *t4997_calloc(size_t nmemb, size_t size)
{
  if(t4997_fail) {
    t4997_fail = FALSE;
    t4997_injected = TRUE;
    return NULL;
  }
  /* !checksrc! disable BANNEDFUNC 1 */
  return calloc(nmemb, size);
}

static char *t4997_strdup(const char *str)
{
  return CURLX_STRDUP_LOW(str);
}

static void t4997_stop(CURL *easy)
{
  t4997_fail = FALSE;
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static void t4997_check(struct Curl_easy *data, const char *expected)
{
  struct curl_slist *cookies = NULL;
  unsigned int i;
  unsigned int count = 0;
  CURLcode result = curl_easy_getinfo(data, CURLINFO_COOKIELIST, &cookies);
  if(result) {
    fail("get cookies failed");
    return;
  }
  fail_unless(cookies && !cookies->next && !strcmp(cookies->data, expected),
              "replacement must preserve the cookie value");
  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    struct Curl_llist_node *n;
    for(n = Curl_llist_head(&data->cookies->cookielist[i]); n;
        n = Curl_node_next(n)) {
      struct Cookie *co = Curl_node_elem(n);
      count++;
      fail_unless(co->creationtime == 1,
                  "replacement must preserve cookie creation order");
    }
  }
  fail_unless(count == 1 && count == data->cookies->numcookies,
              "jar count must equal the stored cookie count");
  fail_unless(data->cookies->lastct == 1,
              "replacement must not advance creation time");
  curl_slist_free_all(cookies);
}
#endif

static CURLcode test_unit4997(const char *arg)
{
#ifndef CURL_DISABLE_COOKIES
  CURL *easy = NULL;
  struct Curl_easy *data;
  CURLcode result;
  const char *oldcookie = "example.com\tFALSE\t/\tFALSE\t0\tsid\told";
  const char *newcookie = "example.com\tFALSE\t/\tFALSE\t0\tsid\tnew";

  UNITTEST_BEGIN_SIMPLE

  result = curl_global_init_mem(CURL_GLOBAL_ALL, malloc, free, realloc,
                                t4997_strdup, t4997_calloc);
  abort_unless(result == CURLE_OK, "global init failed");
  easy = curl_easy_init();
  abort_unless(easy, "easy init failed");
  data = (struct Curl_easy *)easy;
  result = curl_easy_setopt(easy, CURLOPT_COOKIELIST, oldcookie);
  abort_unless(result == CURLE_OK, "initial cookie failed");

  /* Fail the allocation of the owned cookie, after acceptance. */
  t4997_injected = FALSE;
  t4997_fail = TRUE;
  result = curl_easy_setopt(easy, CURLOPT_COOKIELIST, newcookie);
  t4997_fail = FALSE;
  abort_unless(t4997_injected && result == CURLE_OUT_OF_MEMORY,
               "cookie allocation failure not reached");
  t4997_check(data, oldcookie);

  result = curl_easy_setopt(easy, CURLOPT_COOKIELIST, newcookie);
  abort_unless(result == CURLE_OK, "retry failed");
  t4997_check(data, newcookie);

  UNITTEST_END(t4997_stop(easy))
#else
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
#endif
}
