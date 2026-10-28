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
#include "first.h"

/* SameSite and Partitioned cookies evaluated with CURLOPT_COOKIE_SITE and
   CURLOPT_COOKIE_CONTEXT. The request sequence is checked by the test server
   and the resulting cookie jar by the test harness. The last requests go to
   "localhost", a secure context, resolved to the test server: a Partitioned
   cookie received on a cross-site top-level navigation is keyed by the site
   navigated to and sent again for that site only. */

#define T1923_GET          0
#define T1923_CUSTOM_POST  1 /* POST via CURLOPT_CUSTOMREQUEST */
#define T1923_POST         2 /* POST with an empty body */
#define T1923_POST_REDIR   3 /* custom POST, following a 303 to a GET */

#define T1923_SITE_HOST     "<host>"   /* the test server host */
#define T1923_SITE_HOST_DOT "<host.>"  /* the host with a trailing dot */

struct t1923_req {
  int num;           /* number of the request, selects the test data */
  const char *site;  /* CURLOPT_COOKIE_SITE, NULL for none */
  long context;      /* CURLOPT_COOKIE_CONTEXT */
  int method;        /* T1923_* */
  int local;         /* request "localhost" instead of the URL host */
};

static CURLcode test_lib1923(const char *URL)
{
  static const struct t1923_req reqs[] = {
    /* 1: cross-site subresource request */
    { 1, "other.example", 0L, T1923_GET, FALSE },
    /* 2: cross-site top-level navigation */
    { 2, "other.example", CURLCOOKIE_NAVIGATION, T1923_GET, FALSE },
    /* 3: same-site request, the site is given with a trailing dot */
    { 3, T1923_SITE_HOST_DOT, 0L, T1923_GET, FALSE },
    /* 4: cross-site POST, no navigation */
    { 4, "other.example", 0L, T1923_CUSTOM_POST, FALSE },
    /* 5: cross-site POST navigation, unsafe method */
    { 5, "other.example", CURLCOOKIE_NAVIGATION, T1923_POST, FALSE },
    /* 6: cross-site navigation again, now with Lax cookies to send */
    { 6, "other.example", CURLCOOKIE_NAVIGATION, T1923_GET, FALSE },
    /* 7: cross-site POST navigation redirected with 303 to a GET (8) */
    { 7, "other.example", CURLCOOKIE_NAVIGATION, T1923_POST_REDIR, FALSE },
    /* 9: no site given, all cookies are sent, a Partitioned cookie is
       received without a site */
    { 9, NULL, 0L, T1923_GET, FALSE },
    /* 10: cross-site, the Partitioned cookie from 9 is not sent */
    { 10, "other.example", 0L, T1923_GET, FALSE },
    /* 11: same-site, the Partitioned cookie from 9 is sent */
    { 11, T1923_SITE_HOST, 0L, T1923_GET, FALSE },
    /* 12: a link on other.example is followed to localhost, the response
           sets a Partitioned cookie keyed by localhost */
    { 12, "other.example", CURLCOOKIE_NAVIGATION, T1923_GET, TRUE },
    /* 13: a subresource of a page on localhost gets the cookie */
    { 13, "LocalHost.", 0L, T1923_GET, TRUE },
    /* 14: a subresource of a page on other.example does not */
    { 14, "other.example", 0L, T1923_GET, TRUE },
    /* 15: another navigation to localhost gets it again */
    { 15, "other.example", CURLCOOKIE_NAVIGATION, T1923_GET, TRUE }
  };
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  struct curl_slist *resolve = NULL;
  char *host = NULL;
  char *host_dot = NULL;
  char *port = NULL;
  char *local = NULL;  /* the URL with "localhost" as host */
  char *entry = NULL;
  char *url = NULL;
  size_t i;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(!curl) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* the test server host, to make same-site requests for, and the URL
     with "localhost" as host, resolved to the test server address */
  {
    CURLU *u = curl_url();
    if(!u || curl_url_set(u, CURLUPART_URL, URL, 0) ||
       curl_url_get(u, CURLUPART_HOST, &host, 0) ||
       curl_url_get(u, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) ||
       curl_url_set(u, CURLUPART_HOST, "localhost", 0) ||
       curl_url_get(u, CURLUPART_URL, &local, 0)) {
      curl_url_cleanup(u);
      result = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    curl_url_cleanup(u);
    host_dot = curl_maprintf("%s.", host);
    entry = curl_maprintf("localhost:%s:%s", port, host);
    if(!host_dot || !entry) {
      result = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    resolve = curl_slist_append(NULL, entry);
  }

  easy_setopt(curl, CURLOPT_RESOLVE, resolve);
  easy_setopt(curl, CURLOPT_COOKIEFILE, libtest_arg2);
  easy_setopt(curl, CURLOPT_COOKIEJAR, libtest_arg2);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  for(i = 0; i < CURL_ARRAYSIZE(reqs); i++) {
    const char *site = reqs[i].site;
    url = curl_maprintf("%s%04d", reqs[i].local ? local : URL, reqs[i].num);
    if(!url) {
      result = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    if(site && !strcmp(site, T1923_SITE_HOST))
      site = host;
    else if(site && !strcmp(site, T1923_SITE_HOST_DOT))
      site = host_dot;
    easy_setopt(curl, CURLOPT_URL, url);
    curlx_safefree(url);
    easy_setopt(curl, CURLOPT_COOKIE_SITE, site);
    easy_setopt(curl, CURLOPT_COOKIE_CONTEXT, reqs[i].context);
    easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    switch(reqs[i].method) {
    case T1923_CUSTOM_POST:
      easy_setopt(curl, CURLOPT_HTTPGET, 1L);
      easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
      break;
    case T1923_POST_REDIR:
      easy_setopt(curl, CURLOPT_HTTPGET, 1L);
      easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
      /* obey the 303 and switch to GET, ignoring the custom method */
      easy_setopt(curl, CURLOPT_FOLLOWLOCATION, (long)CURLFOLLOW_OBEYCODE);
      break;
    case T1923_POST:
      easy_setopt(curl, CURLOPT_CUSTOMREQUEST, NULL);
      easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
      easy_setopt(curl, CURLOPT_POSTFIELDS, "");
      break;
    default:
      easy_setopt(curl, CURLOPT_CUSTOMREQUEST, NULL);
      easy_setopt(curl, CURLOPT_HTTPGET, 1L);
      break;
    }
    result = curl_easy_perform(curl);
    if(result) {
      curl_mfprintf(stderr, "request %d failed: %d\n", reqs[i].num,
                    (int)result);
      goto test_cleanup;
    }
  }

  /* a site that would break the cookie jar is refused */
  if(curl_easy_setopt(curl, CURLOPT_COOKIE_SITE, "bad site") !=
     CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "a site with a space was accepted\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

test_cleanup:
  curlx_free(url);
  curlx_free(entry);
  curlx_free(host_dot);
  curl_free(local);
  curl_free(port);
  curl_free(host);
  curl_slist_free_all(resolve);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
