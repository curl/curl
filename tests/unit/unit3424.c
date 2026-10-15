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

static CURLcode test_unit3424(const char *arg)
{
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  CURLM *multi = NULL;
  struct Curl_easy *easy = NULL;
  struct Curl_easy *loaded = NULL;
  char host[254];
  char header[MAX_COOKIE_LINE + 1];
  char path[6002];
  struct curl_slist *before = NULL;
  struct curl_slist *after = NULL;
  struct curl_slist *a;
  struct curl_slist *b;
  size_t i;
  const char *jar = "unit3424-cookies.jar";

  (void)arg;

  abort_unless(!curl_global_init(CURL_GLOBAL_ALL), "global init");
  easy = curl_easy_init();
  loaded = curl_easy_init();
  abort_unless(easy && loaded, "easy init");
  multi = curl_multi_init();
  abort_unless(multi, "multi init");
  abort_unless(!curl_multi_add_handle(multi, easy), "add source handle");
  abort_unless(!curl_multi_add_handle(multi, loaded), "add target handle");
  easy->cookies = Curl_cookie_init();
  abort_unless(easy->cookies, "cookie init");
  Curl_cookie_run(easy);
  memset(host, 'a', sizeof(host) - 1);
  host[63] = host[127] = host[191] = '.';
  host[sizeof(host) - 1] = 0;
  memcpy(header, "long=value; Path=/", 18);
  memset(header + 18, 'p', sizeof(header) - 19);
  header[sizeof(header) - 1] = 0;
  fail_unless(!Curl_cookie_add(easy, easy->cookies, header, host, "/",
                               COOKIE_HTTPHEADER | COOKIE_SECURE),
              "long-path Set-Cookie acceptance");
  memset(path, 'q', sizeof(path) - 1);
  path[0] = '/';
  path[sizeof(path) - 2] = '/';
  path[sizeof(path) - 1] = 0;
  fail_unless(!Curl_cookie_add(easy, easy->cookies, "default=value",
                               host, path, COOKIE_HTTPHEADER | COOKIE_SECURE),
              "default path from long URL");
  fail_unless(!Curl_cookie_add(easy, easy->cookies, "short=value; Path=/",
                               "example.com", "/", COOKIE_HTTPHEADER),
              "ordinary cookie acceptance");
  before = Curl_cookie_list(easy);
  abort_unless(before, "serialized cookie list");
  abort_unless(!curl_easy_setopt(easy, CURLOPT_COOKIEJAR, jar),
               "set cookie jar");
  Curl_flush_cookies(easy, FALSE);
  abort_unless(!curl_easy_setopt(loaded, CURLOPT_COOKIEFILE, jar),
               "set cookie file");
  fail_unless(!Curl_cookie_loadfiles(loaded, 0),
              "self-generated cookie jar could not be reloaded");
  after = Curl_cookie_list(loaded);
  for(a = before, i = 0; a; a = a->next, ++i) {
    for(b = after; b && strcmp(a->data, b->data); b = b->next)
      ;
    fail_unless(b, "cookie changed during round trip");
  }
  fail_unless(i == 3, "source cookie rows missing");
  for(b = after, i = 0; b; b = b->next, ++i)
    ;
  fail_unless(i == 3, "cookie rows lost during round trip");
unit_test_abort:
  curl_slist_free_all(before);
  curl_slist_free_all(after);
  if(multi && easy)
    curl_multi_remove_handle(multi, easy);
  if(multi && loaded)
    curl_multi_remove_handle(multi, loaded);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(easy);
  curl_easy_cleanup(loaded);
  unlink(jar);
  curl_global_cleanup();
#else
  (void)arg;
#endif
  return (CURLcode)unitfail;
}
