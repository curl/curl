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

#if defined(HAVE_SOCKETPAIR) && defined(AF_UNIX)

/* A response much like what a large web site sends, in pieces since C89
   compilers need not support string literals longer than 509 bytes */
static const char *const resp_typical[] = {
  "HTTP/1.1 200 OK\r\n"
  "Date: Thu, 23 Oct 2026 10:00:00 GMT\r\n"
  "Content-Type: text/html; charset=utf-8\r\n"
  "Content-Length: 2\r\n"
  "Vary: X-PJAX, X-PJAX-Container, Turbo-Visit, Turbo-Frame, "
  "Accept-Encoding, Accept, X-Requested-With\r\n"
  "ETag: W/\"9b2f6c1d0e8a4b7c3f5e2d1a0b9c8d7e\"\r\n"
  "Cache-Control: max-age=0, private, must-revalidate\r\n"
  "Strict-Transport-Security: max-age=31536000; includeSubdomains; "
  "preload\r\n",
  "X-Frame-Options: deny\r\n"
  "X-Content-Type-Options: nosniff\r\n"
  "X-XSS-Protection: 0\r\n"
  "Referrer-Policy: origin-when-cross-origin, "
  "strict-origin-when-cross-origin\r\n"
  "Content-Security-Policy: default-src 'none'; base-uri 'self'; "
  "child-src 'self' blob:; connect-src 'self' api.example.com "
  "*.example.net wss://live.example.com; font-src assets.example.com; ",
  "form-action 'self' example.com; frame-ancestors 'none'; img-src 'self' "
  "data: blob: assets.example.com *.examplecdn.com; manifest-src 'self'; "
  "media-src example.com; script-src assets.example.com; style-src "
  "'unsafe-inline' assets.example.com; upgrade-insecure-requests; "
  "worker-src assets.example.com blob:\r\n",
  "Set-Cookie: _session=c2Vzc2lvbi12YWx1ZS1mb3ItdGVzdGluZy1vbmx5%3D"
  "--1a2b3c4d5e6f; path=/; secure; HttpOnly; SameSite=Lax\r\n"
  "Set-Cookie: _visit=GH1.1.123456789.1761210000; Path=/; "
  "Domain=example.com; Expires=Fri, 23 Oct 2027 10:00:00 GMT; Secure; "
  "SameSite=Lax\r\n"
  "Set-Cookie: logged_in=no; Path=/; Domain=example.com; "
  "Expires=Fri, 23 Oct 2027 10:00:00 GMT; HttpOnly; Secure; "
  "SameSite=Lax\r\n",
  "Accept-Ranges: bytes\r\n"
  "Via: 1.1 varnish\r\n"
  "Age: 0\r\n"
  "X-Served-By: cache-ams21000-AMS\r\n"
  "X-Cache: MISS\r\n"
  "X-Cache-Hits: 0\r\n"
  "X-Timer: S1761210000.123456,VS0,VE120\r\n"
  "Server-Timing: total;dur=118, db;dur=23, view;dur=41\r\n"
  "X-Request-Id: 7f3c2a1b-9d8e-4f6a-b5c4-3d2e1f0a9b8c\r\n"
  "Alt-Svc: h3=\":443\"; ma=86400\r\n"
  "Server: perf\r\n"
  "\r\n"
  "ok"
};

static const char resp_small[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/plain\r\n"
  "Date: Thu, 23 Oct 2026 10:00:00 GMT\r\n"
  "Server: perf\r\n"
  "Cache-Control: max-age=60\r\n"
  "Content-Length: 2\r\n"
  "\r\n"
  "ok";

#define MANY_HEADERS 200

struct respctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
  const char *resp;
  size_t resplen;
  bool handed_out;
};

static curl_socket_t rh_opensocket(void *clientp, curlsocktype purpose,
                                   struct curl_sockaddr *address)
{
  struct respctx *ctx = clientp;
  (void)purpose;
  (void)address;
  if(ctx->handed_out)
    return CURL_SOCKET_BAD; /* the one connection should be reused */
  ctx->handed_out = TRUE;
  return ctx->sock[0];
}

static int rh_sockopt(void *clientp, curl_socket_t curlfd,
                      curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static int rh_closesocket(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0; /* closed at the end of the test */
}

/* Called after the connection is picked, before the request is sent:
   discard the previous request and queue the next response. Doing it
   earlier would make the idle connection look dead. */
static int rh_prereq(void *clientp, char *conn_primary_ip,
                     char *conn_local_ip, int conn_primary_port,
                     int conn_local_port)
{
  struct respctx *ctx = clientp;
  char buf[4096];
  size_t left = ctx->resplen;
  const char *p = ctx->resp;
  (void)conn_primary_ip;
  (void)conn_local_ip;
  (void)conn_primary_port;
  (void)conn_local_port;

  while(sread(ctx->sock[1], buf, sizeof(buf)) > 0)
    ;
  while(left) {
    ssize_t n = swrite(ctx->sock[1], p, left);
    if(n <= 0)
      return CURL_PREREQFUNC_ABORT;
    p += n;
    left -= (size_t)n;
  }
  return CURL_PREREQFUNC_OK;
}

/* The whole response is queued before libcurl reads any of it, so it must
   fit in the socket buffers. Ask for more room than the default, which is
   only 8 KiB on some systems, and check that a response fits. */
static bool rh_fits(struct respctx *ctx)
{
  int size = 256 * 1024;
  char buf[4096];
  const char *p = ctx->resp;
  size_t left = ctx->resplen;
  size_t got = 0;

  (void)setsockopt(ctx->sock[1], SOL_SOCKET, SO_SNDBUF,
                   (void *)&size, sizeof(size));
  (void)setsockopt(ctx->sock[0], SOL_SOCKET, SO_RCVBUF,
                   (void *)&size, sizeof(size));
  while(left) {
    ssize_t n = swrite(ctx->sock[1], p, left);
    if(n <= 0)
      break;
    p += n;
    left -= (size_t)n;
  }
  /* read back what was written to leave the socket pair empty */
  while(got < ctx->resplen - left) {
    ssize_t n = sread(ctx->sock[0], buf, sizeof(buf));
    if(n <= 0)
      return FALSE;
    got += (size_t)n;
  }
  return !left;
}

static size_t rh_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static int run_one(const char *name, const char *resp, size_t resplen,
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
    curl_mfprintf(stderr, "%s: a %zu byte response does not fit in the "
                  "socket buffers\n", name, resplen);
    rc = 1;
    goto out;
  }

  curl = curl_easy_init();
  if(!curl) {
    rc = 1;
    goto out;
  }
  curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:1/");
  curl_easy_setopt(curl, CURLOPT_PROXY, "");
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, rh_opensocket);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, rh_sockopt);
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, rh_closesocket);
  curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, rh_prereq);
  curl_easy_setopt(curl, CURLOPT_PREREQDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rh_write);

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    CURLcode result = curl_easy_perform(curl);
    if(result) {
      curl_mfprintf(stderr, "%s: transfer %" CURL_FORMAT_CURL_OFF_T
                    " failed: %s\n", name, loop, curl_easy_strerror(result));
      rc = 1;
      break;
    }
  }
  end = curlx_now();
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = loop ? us * 100000 / loop : 0; /* 100 times too big */
  curl_mprintf("%-8s %" CURL_FORMAT_CURL_OFF_T " loops, %lld usecs, "
               "%lld.%02lld ns/loop\n",
               name, loop, (long long)us,
               (long long)hn / 100, (long long)hn % 100);
  curl_easy_cleanup(curl);
out:
  sclose(ctx.sock[0]);
  sclose(ctx.sock[1]);
  return rc;
}

static int test_respheaders(int argc, const char **argv)
{
  static char typical[4096];
  static char many[64 * 1024];
  curl_off_t loops = 50000;
  size_t tlen = 0;
  size_t len;
  int rc = 0;
  int i;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  for(i = 0; i < (int)CURL_ARRAYSIZE(resp_typical); i++)
    tlen += (size_t)curl_msnprintf(&typical[tlen], sizeof(typical) - tlen,
                                   "%s", resp_typical[i]);

  /* a response with lots of headers */
  len = (size_t)curl_msnprintf(many, sizeof(many),
                               "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n");
  for(i = 0; i < MANY_HEADERS; i++)
    len += (size_t)curl_msnprintf(&many[len], sizeof(many) - len,
                                  "X-Header-%03d: some typical header "
                                  "value text, max-age=3600; path=/\r\n", i);
  len += (size_t)curl_msnprintf(&many[len], sizeof(many) - len, "\r\nok");

  curl_global_init(CURL_GLOBAL_ALL);
  rc |= run_one("small", resp_small, sizeof(resp_small) - 1, loops);
  rc |= run_one("typical", typical, tlen, loops);
  rc |= run_one("many", many, len, loops / 4);
  curl_global_cleanup();
  return rc;
}

#else

static int test_respheaders(int argc, const char **argv)
{
  (void)argc;
  (void)argv;
  curl_mfprintf(stderr, "respheaders needs socketpair()\n");
  return 0;
}

#endif
