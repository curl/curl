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

#if defined(HAVE_SOCKETPAIR) && defined(AF_UNIX) && \
  !defined(CURL_DISABLE_WEBSOCKETS)

/* libcurl does not check Sec-WebSocket-Accept, so any value works */
static const char ws_upgrade[] =
  "HTTP/1.1 101 Switching Protocols\r\n"
  "Upgrade: websocket\r\n"
  "Connection: Upgrade\r\n"
  "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
  "\r\n";

struct wsctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
};

static curl_socket_t ws_opensocket(void *clientp, curlsocktype purpose,
                                   struct curl_sockaddr *address)
{
  struct wsctx *ctx = clientp;
  (void)purpose;
  (void)address;
  return ctx->sock[0];
}

static int ws_sockopt(void *clientp, curl_socket_t curlfd,
                      curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static int ws_closesocket(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0; /* closed at the end of the test */
}

/* queue the upgrade response before the request goes out */
static int ws_prereq(void *clientp, char *conn_primary_ip,
                     char *conn_local_ip, int conn_primary_port,
                     int conn_local_port)
{
  struct wsctx *ctx = clientp;
  (void)conn_primary_ip;
  (void)conn_local_ip;
  (void)conn_primary_port;
  (void)conn_local_port;

  if(swrite(ctx->sock[1], ws_upgrade, sizeof(ws_upgrade) - 1) !=
     (ssize_t)(sizeof(ws_upgrade) - 1))
    return CURL_PREREQFUNC_ABORT;
  return CURL_PREREQFUNC_OK;
}

/* the "server" reads and drops everything libcurl has sent so far */
static void ws_drain(struct wsctx *ctx)
{
  char buf[16384];
  while(sread(ctx->sock[1], buf, sizeof(buf)) > 0)
    ;
}

static int ws_run_one(const char *name, const unsigned char *payload,
                      size_t plen, curl_off_t loops)
{
  struct wsctx ctx;
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;
  curl_off_t loop;
  CURLcode result;
  CURL *curl;
  int size = 256 * 1024;
  int rc = 0;

  memset(&ctx, 0, sizeof(ctx));
  if(CURL_SOCKETPAIR(AF_UNIX, SOCK_STREAM, 0, ctx.sock)) {
    curl_mfprintf(stderr, "socketpair() failed\n");
    return 1;
  }
  if(curlx_nonblock(ctx.sock[1], TRUE)) {
    curl_mfprintf(stderr, "curlx_nonblock() failed\n");
    rc = 1;
    goto out;
  }
  /* fewer round trips to the drain with larger buffers */
  (void)setsockopt(ctx.sock[0], SOL_SOCKET, SO_SNDBUF,
                   (void *)&size, sizeof(size));
  (void)setsockopt(ctx.sock[1], SOL_SOCKET, SO_RCVBUF,
                   (void *)&size, sizeof(size));

  curl = curl_easy_init();
  if(!curl) {
    rc = 1;
    goto out;
  }
  curl_easy_setopt(curl, CURLOPT_URL, "ws://127.0.0.1:1/");
  curl_easy_setopt(curl, CURLOPT_PROXY, "");
  curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, ws_opensocket);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, ws_sockopt);
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, ws_closesocket);
  curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, ws_prereq);
  curl_easy_setopt(curl, CURLOPT_PREREQDATA, &ctx);

  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr, "%s: upgrade failed: %s\n", name,
                  curl_easy_strerror(result));
    rc = 1;
    goto cleanup;
  }
  ws_drain(&ctx); /* the upgrade request */

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    size_t off = 0;
    while(off < plen) {
      size_t sent = 0;
      result = curl_ws_send(curl, payload + off, plen - off, &sent, 0,
                            CURLWS_BINARY);
      if(result == CURLE_AGAIN)
        ws_drain(&ctx);
      else if(result) {
        curl_mfprintf(stderr, "%s: frame %" CURL_FORMAT_CURL_OFF_T
                      " failed: %s\n", name, loop,
                      curl_easy_strerror(result));
        rc = 1;
        goto cleanup;
      }
      else if(sent < plen - off)
        ws_drain(&ctx);
      off += sent;
    }
  }
  end = curlx_now();
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = loop ? us * 100000 / loop : 0; /* 100 times too big */
  curl_mprintf("%-8s %" CURL_FORMAT_CURL_OFF_T " frames, %lld usecs, "
               "%lld.%02lld ns/frame, %lld MB/s\n",
               name, loop, (long long)us,
               (long long)hn / 100, (long long)hn % 100,
               us ? (long long)(loop * (curl_off_t)plen / us) : 0LL);
cleanup:
  curl_easy_cleanup(curl);
out:
  sclose(ctx.sock[0]);
  sclose(ctx.sock[1]);
  return rc;
}

static int test_wssend(int argc, const char **argv)
{
  static unsigned char payload[16384];
  curl_off_t loops = 500000;
  size_t i;
  int rc = 0;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  for(i = 0; i < sizeof(payload); i++)
    payload[i] = (unsigned char)i;

  curl_global_init(CURL_GLOBAL_ALL);
  rc |= ws_run_one("16", payload, 16, loops);
  rc |= ws_run_one("125", payload, 125, loops);
  rc |= ws_run_one("1024", payload, 1024, loops);
  rc |= ws_run_one("16384", payload, 16384, loops / 16);
  curl_global_cleanup();
  return rc;
}

#else

static int test_wssend(int argc, const char **argv)
{
  (void)argc;
  (void)argv;
  curl_mfprintf(stderr, "wssend needs socketpair() and WebSocket support\n");
  return 0;
}

#endif
