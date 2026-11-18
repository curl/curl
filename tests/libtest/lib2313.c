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
static const char t2313_upgrade[] =
  "HTTP/1.1 101 Switching Protocols\r\n"
  "Upgrade: websocket\r\n"
  "Connection: Upgrade\r\n"
  "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
  "\r\n";

/* a PING and a one byte binary frame, as the server sends them */
static const char t2313_ping[] = {
  '\x89', '\x04', 'p', 'i', 'n', 'g', '\x82', '\x01', 'x'
};

static char t2313_payload[200000]; /* all zero */
static unsigned char t2313_rcv[262144];

struct t2313_ctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
  size_t rcvlen;         /* bytes the server has read */
};

static curl_socket_t t2313_opensocket(void *clientp, curlsocktype purpose,
                                      struct curl_sockaddr *address)
{
  struct t2313_ctx *ctx = clientp;
  (void)purpose;
  (void)address;
  return ctx->sock[0];
}

static int t2313_sockopt(void *clientp, curl_socket_t curlfd,
                         curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static int t2313_closesocket(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0; /* closed at the end of the test */
}

/* queue the upgrade response before the request goes out */
static int t2313_prereq(void *clientp, char *conn_primary_ip,
                        char *conn_local_ip, int conn_primary_port,
                        int conn_local_port)
{
  struct t2313_ctx *ctx = clientp;
  (void)conn_primary_ip;
  (void)conn_local_ip;
  (void)conn_primary_port;
  (void)conn_local_port;

  if(swrite(ctx->sock[1], t2313_upgrade, sizeof(t2313_upgrade) - 1) !=
     (ssize_t)(sizeof(t2313_upgrade) - 1))
    return CURL_PREREQFUNC_ABORT;
  return CURL_PREREQFUNC_OK;
}

static void t2313_bufsize(struct t2313_ctx *ctx, int size)
{
  (void)setsockopt(ctx->sock[0], SOL_SOCKET, SO_SNDBUF,
                   (void *)&size, sizeof(size));
  (void)setsockopt(ctx->sock[1], SOL_SOCKET, SO_RCVBUF,
                   (void *)&size, sizeof(size));
}

/* the server reads everything libcurl has sent so far */
static void t2313_drain(struct t2313_ctx *ctx)
{
  for(;;) {
    struct timeval tv = { 0, 0 };
    fd_set rd;
    ssize_t n;

    FD_ZERO(&rd);
    FD_SET(ctx->sock[1], &rd);
    if((ctx->rcvlen == sizeof(t2313_rcv)) ||
       (select((int)ctx->sock[1] + 1, &rd, NULL, NULL, &tv) <= 0))
      break;
    n = sread(ctx->sock[1], &t2313_rcv[ctx->rcvlen],
              sizeof(t2313_rcv) - ctx->rcvlen);
    if(n <= 0)
      break;
    ctx->rcvlen += (size_t)n;
  }
}

/* send the rest of a frame while the server reads */
static CURLcode t2313_send(CURL *curl, struct t2313_ctx *ctx,
                           const char *buf, size_t len)
{
  size_t off = 0;
  int i;

  for(i = 0; (off < len) && (i < 10000); i++) {
    size_t sent = 0;
    CURLcode result = curl_ws_send(curl, buf + off, len - off, &sent, 0,
                                   CURLWS_BINARY);
    if(result && (result != CURLE_AGAIN))
      return result;
    off += sent;
    t2313_drain(ctx);
  }
  return (off < len) ? CURLE_OPERATION_TIMEDOUT : CURLE_OK;
}

#define T2313_GROW_NEVER 0
#define T2313_GROW_BEFORE_RECV 1 /* curl_ws_recv() sends the frame's rest */
#define T2313_GROW_AFTER_RECV 2  /* one more call sends all of it */

/* A frame of 'len' bytes does not fit the socket and a PING arrives. The
   server has to get the frame, the PONG and then 'more', if given. */
static CURLcode t2313_run(size_t len, int grow, const char *more)
{
  struct t2313_ctx ctx;
  const struct curl_ws_frame *meta;
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  char buf[16];
  size_t want = 14 + len + 6 + 4 + (more ? 6 + strlen(more) : 0);
  size_t sent = 0;
  size_t nread = 0;
  int i;

  ctx.rcvlen = 0;
  if(CURL_SOCKETPAIR(AF_UNIX, SOCK_STREAM, 0, ctx.sock))
    return TEST_ERR_MAJOR_BAD;
  t2313_bufsize(&ctx, 4096);

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, "ws://127.0.0.1:1/");
  easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
  easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, t2313_opensocket);
  easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &ctx);
  easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, t2313_sockopt);
  easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, t2313_closesocket);
  easy_setopt(curl, CURLOPT_PREREQFUNCTION, t2313_prereq);
  easy_setopt(curl, CURLOPT_PREREQDATA, &ctx);

  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;
  t2313_drain(&ctx); /* the upgrade request */
  ctx.rcvlen = 0;

  /* most of the frame stays in the send buffer */
  result = curl_ws_send(curl, t2313_payload, len, &sent, 0, CURLWS_BINARY);
  if(result && (result != CURLE_AGAIN))
    goto test_cleanup;
  if(swrite(ctx.sock[1], t2313_ping, sizeof(t2313_ping)) !=
     (ssize_t)sizeof(t2313_ping)) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  if(grow == T2313_GROW_BEFORE_RECV) {
    t2313_bufsize(&ctx, 1024 * 1024);
    t2313_drain(&ctx);
  }

  /* receiving the frame behind the PING makes libcurl queue the PONG */
  result = CURLE_AGAIN;
  for(i = 0; (result == CURLE_AGAIN) && (i < 100); i++) {
    result = curl_ws_recv(curl, buf, sizeof(buf), &nread, &meta);
    if(result == CURLE_AGAIN)
      curlx_wait_ms(10);
  }
  if(result)
    goto test_cleanup;

  if(grow == T2313_GROW_AFTER_RECV)
    t2313_bufsize(&ctx, 1024 * 1024);
  t2313_drain(&ctx);
  result = t2313_send(curl, &ctx, t2313_payload + sent, len - sent);
  if(!result && more)
    result = t2313_send(curl, &ctx, more, strlen(more));
  if(result)
    goto test_cleanup;

  /* no further call: whatever is missing now was never sent */
  for(i = 0; (ctx.rcvlen < want) && (i < 100); i++) {
    curlx_wait_ms(10);
    t2313_drain(&ctx);
  }
  if(ctx.rcvlen != want) {
    curl_mfprintf(stderr, "server got %zu bytes, expected %zu\n",
                  ctx.rcvlen, want);
    result = TEST_ERR_FAILURE;
  }

test_cleanup:
  if(result)
    curl_mfprintf(stderr, "frame of %zu bytes failed: %d\n", len,
                  (int)result);
  curl_easy_cleanup(curl);
  sclose(ctx.sock[0]);
  sclose(ctx.sock[1]);
  return result;
}

static CURLcode test_lib2313(const char *URL)
{
  CURLcode result;

  (void)URL;
  global_init(CURL_GLOBAL_ALL);

  /* the send buffer is two chunks of 65535 bytes: the PONG's head fills
     what this frame leaves and its payload goes beyond the soft limit */
  result = t2313_run((2 * 65535) - 14 - 4, T2313_GROW_NEVER, "0123456789");
  /* the PONG waits for the frame and goes out with its last bytes */
  if(!result)
    result = t2313_run(sizeof(t2313_payload), T2313_GROW_AFTER_RECV, NULL);
  /* receiving sends the rest of the frame, the retry has to notice */
  if(!result)
    result = t2313_run(100000, T2313_GROW_BEFORE_RECV, NULL);

  curl_global_cleanup();
  return result;
}

#else

static CURLcode test_lib2313(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}

#endif
