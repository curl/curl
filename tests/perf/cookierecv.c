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
#include "rh.h"

#if defined(HAVE_SOCKETPAIR) && defined(AF_UNIX)

#define NON_COOKIE_LINES 3

/* A response much like what a large web site sends, in pieces since C89
   compilers need not support string literals longer than 509 bytes */
static const char *resp_cookies[] = {
  "HTTP/1.1 200 OK\r\n",
  "Content-Length: 0\r\n",
  "Set-Cookie: name=content\r\n",
  "Set-Cookie: heyyou=content; path=/path\r\n",
  "Set-Cookie: heyyou2=content; path=/path/first\r\n",
  "Set-Cookie: sameagain=content; path=/path/first\r\n",
  "Set-Cookie: heymiss=content; path=/path/firstfail\r\n",
  "Set-Cookie: another=content; path=/path; domain=www.example\r\n",
  "Set-Cookie: nomatch=content; path=/path; domain=www.mismatch\r\n",
  "Set-Cookie: timeout=content; path=/path; domain=www.example; "
  "expires=\"Fri Feb 13 11:56:27 GMT 2125\"; httponly\r\n",
  "Set-Cookie: notimeleft=content; path=/path; domain=www.example; "
  "expires=\"Tue Nov  3 04:55:04 PM UTC 2026\"; httponly\r\n",
  "Set-Cookie: session=content; path=/path; domain=www.example; "
  "expires=\"Sun Jun  7 04:57:56 PM UTC 2026\"; httponly\r\n",
  "Set-Cookie: identifier=content; path=/path; domain=www.example; "
  "expires=\"Tue Dec  9 04:55:54 PM UTC 2025\"; httponly\r\n",
  "Set-Cookie: whatifthis=content; path=/path; domain=www.example; "
  "expires=\"Wed Sep 15 04:58:54 PM UTC 2032\"; httponly\r\n",
  "Set-Cookie: timer=content; path=/path; domain=www.example; "
  "max-age=2764800; httponly\r\n",
  "Set-Cookie: more=content; path=/path; secure\r\n",
  "Set-Cookie: whatabout=content; path=/path; secur3\r\n",
  "Set-Cookie: curious=content;\tpath=/path;\tdomain=www.example\r\n",
  "Set-COOKIE:\tbare=something;\texpires=\"2044 Nov 6 08:49:37\"\r\n",
  "Set-Cookie: name=overwritten\r\n",
  "\r\n"
};

static int run_cookies(const char * const resp, size_t resplen,
                       unsigned int num_cookies,
                       curl_off_t loops)
{
  struct respctx ctx;
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;
  curl_off_t loop;
  CURL *curl;
  int rc = 0;
  struct curl_slist *list;

  memset(&ctx, 0, sizeof(ctx));
  if(CURL_SOCKETPAIR(AF_UNIX, SOCK_STREAM, 0, ctx.sock)) {
    curl_mfprintf(stderr, "socketpair() failed\n");
    return 1;
  }
  /* the "server" end only reads what is already there */
  if(curlx_nonblock(ctx.sock[1], TRUE)) {
    curl_mfprintf(stderr, "curlx_nonblock() failed\n");
    rc = 1;
    goto out;
  }
  ctx.resp = resp;
  ctx.resplen = resplen;
  if(!rh_fits(&ctx)) {
    curl_mfprintf(stderr, "a %zu byte response does not fit in the "
                  "socket buffers\n", resplen);
    rc = 1;
    goto out;
  }

  list = curl_slist_append(NULL, "www.example:80:127.0.0.1");
  if(!list) {
    rc = 1;
    goto out;
  }

  curl = curl_easy_init();
  if(!curl) {
    rc = 1;
    goto out;
  }
  curl_easy_setopt(curl, CURLOPT_URL, "http://www.example/path/first");
  curl_easy_setopt(curl, CURLOPT_PROXY, "");
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, rh_opensocket);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, rh_sockopt);
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, rh_closesocket);
  curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, rh_prereq);
  curl_easy_setopt(curl, CURLOPT_PREREQDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rh_write);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
  curl_easy_setopt(curl, CURLOPT_RESOLVE, list);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    CURLcode result = curl_easy_perform(curl);
    if(result) {
      curl_mfprintf(stderr, "transfer %" CURL_FORMAT_CURL_OFF_T
                    " failed: %s\n", loop, curl_easy_strerror(result));
      rc = 1;
      break;
    }
  }
  end = curlx_now();
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = loop ? us * 100000 / (loop * num_cookies) : 0; /* 100 times too big */
  curl_mprintf("%" CURL_FORMAT_CURL_OFF_T " loops, %lld usecs, "
               "%lld.%02lld ns/cookie\n"
               "%u cookies per response\n",
               loop, (long long)us,
               (long long)hn / 100, (long long)hn % 100,
               num_cookies);
  curl_easy_cleanup(curl);
  curl_slist_free_all(list);
out:
  sclose(ctx.sock[0]);
  sclose(ctx.sock[1]);
  return rc;
}

static int test_cookierecv(int argc, const char **argv)
{
  static char typical[4096];
  curl_off_t loops = 50000;
  size_t tlen = 0;
  int rc = 0;
  int i;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  for(i = 0; i < (int)CURL_ARRAYSIZE(resp_cookies); i++)
    tlen += (size_t)curl_msnprintf(&typical[tlen], sizeof(typical) - tlen,
                                   "%s", resp_cookies[i]);

  curl_global_init(CURL_GLOBAL_ALL);
  rc |= run_cookies(typical, tlen, i - NON_COOKIE_LINES, loops);
  curl_global_cleanup();
  return rc;
}

#else

static int test_cookierecv(int argc, const char **argv)
{
  (void)argc;
  (void)argv;
  curl_mfprintf(stderr, "cookierecv needs socketpair()\n");
  return 0;
}

#endif
