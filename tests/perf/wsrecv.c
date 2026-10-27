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

/* RFC 6455 sample response for the fixed test key installed below. */
static const char wr_upgrade[] =
  "HTTP/1.1 101 Switching Protocols\r\n"
  "Upgrade: websocket\r\n"
  "Connection: Upgrade\r\n"
  "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
  "\r\n";

/* keep at most this much unread in the socket pair */
#define WR_INFLIGHT (128 * 1024)

struct wrctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
  CURL *curl;
  unsigned char block[64 * 1024]; /* whole frames, sent over and over */
  size_t blocklen;
  size_t blockpos;     /* next byte of block to send */
  size_t flen;         /* bytes of one frame on the wire */
  size_t hlen;         /* bytes of its header */
  size_t closepos;     /* bytes of the CLOSE frame sent */
  curl_off_t towrite;  /* frame bytes still to send */
  curl_off_t written;  /* frame bytes sent */
  curl_off_t frames;   /* complete frames received */
  curl_off_t received; /* frame bytes received */
  bool bad;            /* unexpected frame data */
};

static curl_socket_t wr_opensocket(void *clientp, curlsocktype purpose,
                                   struct curl_sockaddr *address)
{
  struct wrctx *ctx = clientp;
  (void)purpose;
  (void)address;
  return ctx->sock[0];
}

static int wr_sockopt(void *clientp, curl_socket_t curlfd,
                      curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static int wr_closesocket(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0; /* closed at the end of the test */
}

/* drop what libcurl sent, then send frames until enough are in flight,
   and a CLOSE frame after the last one */
static void wr_feed(struct wrctx *ctx)
{
  char buf[4096];
  while(sread(ctx->sock[1], buf, sizeof(buf)) > 0)
    ;
  while(ctx->towrite && (ctx->written - ctx->received < WR_INFLIGHT)) {
    size_t len = ctx->blocklen - ctx->blockpos;
    ssize_t n;
    if((curl_off_t)len > ctx->towrite)
      len = (size_t)ctx->towrite;
    n = swrite(ctx->sock[1], &ctx->block[ctx->blockpos], len);
    if(n <= 0)
      return;
    ctx->blockpos = (ctx->blockpos + (size_t)n) % ctx->blocklen;
    ctx->towrite -= n;
    ctx->written += n;
  }
  while(!ctx->towrite && ctx->closepos < 2) {
    static const unsigned char close_frame[] = { 0x88, 0x00 };
    ssize_t n = swrite(ctx->sock[1], &close_frame[ctx->closepos],
                       sizeof(close_frame) - ctx->closepos);
    if(n <= 0)
      return;
    ctx->closepos += (size_t)n;
  }
}

static int wr_prereq(void *clientp, char *conn_primary_ip,
                     char *conn_local_ip, int conn_primary_port,
                     int conn_local_port)
{
  struct wrctx *ctx = clientp;
  (void)conn_primary_ip;
  (void)conn_local_ip;
  (void)conn_primary_port;
  (void)conn_local_port;

  if(swrite(ctx->sock[1], wr_upgrade, sizeof(wr_upgrade) - 1) !=
     (ssize_t)(sizeof(wr_upgrade) - 1))
    return CURL_PREREQFUNC_ABORT;
  wr_feed(ctx);
  return CURL_PREREQFUNC_OK;
}

/* called with the payload of each frame, as an application would be */
static size_t wr_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct wrctx *ctx = userdata;
  const struct curl_ws_frame *meta = curl_ws_meta(ctx->curl);
  (void)ptr;
  if(meta && (meta->flags & CURLWS_CLOSE))
    ; /* the end */
  else if(!meta || !(meta->flags & CURLWS_BINARY))
    ctx->bad = TRUE;
  else {
    /* a frame can arrive in pieces */
    if(!meta->offset)
      ctx->received += (curl_off_t)ctx->hlen;
    ctx->received += (curl_off_t)(size * nmemb);
    if(!meta->bytesleft)
      ctx->frames++;
    if(ctx->written - ctx->received < WR_INFLIGHT / 2)
      wr_feed(ctx);
  }
  return size * nmemb;
}

static int wr_run_one(const char *name, size_t plen, curl_off_t loops)
{
  static struct wrctx wrctx;
  struct wrctx *ctx = &wrctx;
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;
  CURLcode result;
  struct curl_slist *headers = NULL;
  size_t i;
  int size = 256 * 1024;
  int rc = 0;

  memset(ctx, 0, sizeof(*ctx));
  if(CURL_SOCKETPAIR(AF_UNIX, SOCK_STREAM, 0, ctx->sock)) {
    curl_mfprintf(stderr, "socketpair() failed\n");
    return 1;
  }
  if(curlx_nonblock(ctx->sock[1], TRUE)) {
    curl_mfprintf(stderr, "curlx_nonblock() failed\n");
    rc = 1;
    goto out;
  }
  (void)setsockopt(ctx->sock[1], SOL_SOCKET, SO_SNDBUF,
                   (void *)&size, sizeof(size));
  (void)setsockopt(ctx->sock[0], SOL_SOCKET, SO_RCVBUF,
                   (void *)&size, sizeof(size));

  /* unmasked binary frames, as a server sends them */
  ctx->hlen = plen < 126 ? 2 : 4;
  ctx->flen = ctx->hlen + plen;
  ctx->blocklen = (sizeof(ctx->block) / ctx->flen) * ctx->flen;
  for(i = 0; i < ctx->blocklen; i += ctx->flen) {
    unsigned char *f = &ctx->block[i];
    f[0] = 0x82;
    if(ctx->hlen == 2)
      f[1] = (unsigned char)plen;
    else {
      f[1] = 126;
      f[2] = (unsigned char)(plen >> 8);
      f[3] = (unsigned char)(plen & 0xff);
    }
    memset(f + ctx->hlen, 'x', plen);
  }
  ctx->towrite = loops * (curl_off_t)ctx->flen;

  ctx->curl = curl_easy_init();
  if(!ctx->curl) {
    rc = 1;
    goto out;
  }
  curl_easy_setopt(ctx->curl, CURLOPT_URL, "ws://127.0.0.1:1/");
  headers = curl_slist_append(NULL,
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
  if(!headers) {
    rc = 1;
    goto cleanup;
  }
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(ctx->curl, CURLOPT_PROXY, "");
  curl_easy_setopt(ctx->curl, CURLOPT_OPENSOCKETFUNCTION, wr_opensocket);
  curl_easy_setopt(ctx->curl, CURLOPT_OPENSOCKETDATA, ctx);
  curl_easy_setopt(ctx->curl, CURLOPT_SOCKOPTFUNCTION, wr_sockopt);
  curl_easy_setopt(ctx->curl, CURLOPT_CLOSESOCKETFUNCTION, wr_closesocket);
  curl_easy_setopt(ctx->curl, CURLOPT_PREREQFUNCTION, wr_prereq);
  curl_easy_setopt(ctx->curl, CURLOPT_PREREQDATA, ctx);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, wr_write);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, ctx);
  curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, 120L);

  start = curlx_now();
  result = curl_easy_perform(ctx->curl);
  end = curlx_now();
  if(result || ctx->bad || ctx->frames != loops) {
    curl_mfprintf(stderr, "%s: %s, %" CURL_FORMAT_CURL_OFF_T " of %"
                  CURL_FORMAT_CURL_OFF_T " frames%s\n", name,
                  curl_easy_strerror(result), ctx->frames, loops,
                  ctx->bad ? ", unexpected frame" : "");
    rc = 1;
  }
  else {
    us = curlx_timediff_us(end, start); /* how many microseconds */
    hn = us * 100000 / loops; /* 100 times too big */
    curl_mprintf("%-8s %" CURL_FORMAT_CURL_OFF_T " frames, %lld usecs, "
                 "%lld.%02lld ns/frame, %lld MB/s\n",
                 name, loops, (long long)us,
                 (long long)hn / 100, (long long)hn % 100,
                 us ? (long long)(loops * (curl_off_t)plen / us) : 0LL);
  }
cleanup:
  curl_easy_cleanup(ctx->curl);
  curl_slist_free_all(headers);
out:
  sclose(ctx->sock[0]);
  sclose(ctx->sock[1]);
  return rc;
}

static int test_wsrecv(int argc, const char **argv)
{
  curl_off_t loops = 500000;
  int rc = 0;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr && num)
      loops = num;
  }

  curl_global_init(CURL_GLOBAL_ALL);
  rc |= wr_run_one("16", 16, loops);
  rc |= wr_run_one("125", 125, loops);
  rc |= wr_run_one("1024", 1024, loops);
  rc |= wr_run_one("16384", 16384, loops / 16 ? loops / 16 : 1);
  curl_global_cleanup();
  return rc;
}

#else

static int test_wsrecv(int argc, const char **argv)
{
  (void)argc;
  (void)argv;
  curl_mfprintf(stderr, "wsrecv needs socketpair() and WebSocket support\n");
  return 0;
}

#endif
