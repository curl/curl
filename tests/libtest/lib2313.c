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

/* The send buffer is two chunks of 65535 bytes and the head of a frame
   larger than 65535 bytes takes 14 bytes. A frame of this size leaves room
   for 4 bytes: the buffer is not full, the 6 byte head of a PONG fills it
   and the PONG payload has to go beyond its soft limit. */
#define T2313_BOUNDARY ((2 * 65535) - 14 - 4)

static char t2313_payload[200000]; /* all zero */
static unsigned char t2313_rcv[262144];

struct t2313_ctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
  size_t rcvlen;         /* bytes in t2313_rcv */
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

/* the "server" reads everything libcurl has sent so far */
static void t2313_drain(struct t2313_ctx *ctx)
{
  for(;;) {
    struct timeval tv = { 0, 0 };
    fd_set rd;
    ssize_t n;

    if(ctx->rcvlen == sizeof(t2313_rcv))
      break;
    FD_ZERO(&rd);
    FD_SET(ctx->sock[1], &rd);
    if(select((int)ctx->sock[1] + 1, &rd, NULL, NULL, &tv) <= 0)
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

/* a masked frame at 'p': returns its size, 0 when it is not as expected */
static size_t t2313_frame(const unsigned char *p, size_t avail,
                          unsigned char opcode, const char *payload,
                          size_t len)
{
  size_t hlen = (len > 65535) ? 14 : 6;
  const unsigned char *mask;
  size_t i;

  if((avail < hlen + len) || (p[0] != (0x80 | opcode)))
    return 0;
  if(len > 65535) {
    if((p[1] != 0xff) || p[2] || p[3] || p[4] || p[5] || p[6] ||
       (p[7] != ((len >> 16) & 0xff)) || (p[8] != ((len >> 8) & 0xff)) ||
       (p[9] != (len & 0xff)))
      return 0;
  }
  else if(p[1] != (0x80 | len))
    return 0;
  mask = &p[hlen - 4];
  for(i = 0; i < len; i++) {
    if((p[hlen + i] ^ mask[i & 3]) != (unsigned char)payload[i])
      return 0;
  }
  return hlen + len;
}

/* the server has to see the first frame, the PONG and the second frame */
static CURLcode t2313_verify(struct t2313_ctx *ctx, size_t len,
                             const char *second, size_t slen)
{
  size_t want = 14 + len + 6 + 4 + 6 + slen;
  size_t off = 0;
  size_t n;
  int i;

  for(i = 0; (ctx->rcvlen < want) && (i < 100); i++) {
    curlx_wait_ms(10);
    t2313_drain(ctx);
  }
  if(ctx->rcvlen != want) {
    curl_mfprintf(stderr, "server got %zu bytes, expected %zu\n",
                  ctx->rcvlen, want);
    return TEST_ERR_FAILURE;
  }
  n = t2313_frame(t2313_rcv, ctx->rcvlen, 0x2, t2313_payload, len);
  if(!n) {
    curl_mfprintf(stderr, "first frame is damaged\n");
    return TEST_ERR_FAILURE;
  }
  off += n;
  n = t2313_frame(&t2313_rcv[off], ctx->rcvlen - off, 0xa, "ping", 4);
  if(!n) {
    curl_mfprintf(stderr, "PONG is missing or incomplete\n");
    return TEST_ERR_FAILURE;
  }
  off += n;
  n = t2313_frame(&t2313_rcv[off], ctx->rcvlen - off, 0x2, second, slen);
  if(!n) {
    curl_mfprintf(stderr, "second frame is damaged\n");
    return TEST_ERR_FAILURE;
  }
  return CURLE_OK;
}

/* A PING arrives while a frame of 'len' bytes sits in the send buffer.
   With 'boundary' the PONG is queued behind it, both are sent and another
   frame follows. Without, the send buffer is full and starting a frame has
   to flush it first. */
static CURLcode t2313_run(size_t len, bool boundary)
{
  static const char second[] = "0123456789";
  struct t2313_ctx ctx;
  const struct curl_ws_frame *meta;
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  char buf[256];
  size_t sent = 0;
  size_t nread = 0;
  int size = 4096;
  int i;

  ctx.rcvlen = 0;
  if(CURL_SOCKETPAIR(AF_UNIX, SOCK_STREAM, 0, ctx.sock)) {
    curl_mfprintf(stderr, "socketpair() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  /* small buffers, the large frame must not fit */
  (void)setsockopt(ctx.sock[0], SOL_SOCKET, SO_SNDBUF,
                   (void *)&size, sizeof(size));
  (void)setsockopt(ctx.sock[1], SOL_SOCKET, SO_RCVBUF,
                   (void *)&size, sizeof(size));

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
  if(result) {
    curl_mfprintf(stderr, "upgrade failed: %s\n",
                  curl_easy_strerror(result));
    goto test_cleanup;
  }
  t2313_drain(&ctx); /* the upgrade request */
  ctx.rcvlen = 0;

  /* the socket blocks, most of the frame stays in the send buffer */
  result = curl_ws_send(curl, t2313_payload, len, &sent, 0, CURLWS_BINARY);
  if(result && (result != CURLE_AGAIN)) {
    curl_mfprintf(stderr, "curl_ws_send() failed: %s\n",
                  curl_easy_strerror(result));
    goto test_cleanup;
  }

  if(swrite(ctx.sock[1], t2313_ping, sizeof(t2313_ping)) !=
     (ssize_t)sizeof(t2313_ping)) {
    curl_mfprintf(stderr, "sending PING failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* receiving the frame behind the PING makes libcurl queue the PONG */
  result = CURLE_AGAIN;
  for(i = 0; (result == CURLE_AGAIN) && (i < 100); i++) {
    result = curl_ws_recv(curl, buf, sizeof(buf), &nread, &meta);
    if(result == CURLE_AGAIN)
      curlx_wait_ms(10);
  }
  if(result || (nread != 1) || (buf[0] != 'x')) {
    curl_mfprintf(stderr, "curl_ws_recv() failed: %s\n",
                  curl_easy_strerror(result));
    if(!result)
      result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  if(boundary) {
    result = t2313_send(curl, &ctx, t2313_payload + sent, len - sent);
    if(!result)
      result = t2313_send(curl, &ctx, second, sizeof(second) - 1);
    if(result) {
      curl_mfprintf(stderr, "curl_ws_send() after PING failed: %s\n",
                    curl_easy_strerror(result));
      goto test_cleanup;
    }
    result = t2313_verify(&ctx, len, second, sizeof(second) - 1);
  }
  else {
    /* the PONG has to wait for the send buffer, a new frame can be started
       once the server has read what is ahead of it */
    result = CURLE_AGAIN;
    for(i = 0; result && (i < 1000); i++) {
      result = curl_ws_start_frame(curl, CURLWS_BINARY, 10);
      t2313_drain(&ctx);
    }
    if(result)
      curl_mfprintf(stderr, "curl_ws_start_frame() failed: %s\n",
                    curl_easy_strerror(result));
  }

test_cleanup:
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

  /* the send buffer is full when the PING arrives */
  result = t2313_run(sizeof(t2313_payload), FALSE);
  /* the send buffer is filled by the head of the PONG */
  if(!result)
    result = t2313_run(T2313_BOUNDARY, TRUE);

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
