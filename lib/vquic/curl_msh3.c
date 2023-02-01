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

#include "curl_setup.h"

#ifdef USE_MSH3

#include "urldata.h"
#include "timeval.h"
#include "multiif.h"
#include "sendf.h"
#include "curl_log.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "h2h3.h"
#include "curl_msh3.h"
#include "socketpair.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define DEBUG_CF 1

#if DEBUG_CF && defined(DEBUGBUILD)
#define CF_DEBUGF(x) x
#else
#define CF_DEBUGF(x) do { } while(0)
#endif

#define MSH3_REQ_INIT_BUF_LEN 16384
#define MSH3_REQ_MAX_BUF_LEN 0x100000

#ifdef _WIN32
#define msh3_lock CRITICAL_SECTION
#define msh3_lock_initialize(lock) InitializeCriticalSection(lock)
#define msh3_lock_uninitialize(lock) DeleteCriticalSection(lock)
#define msh3_lock_acquire(lock) EnterCriticalSection(lock)
#define msh3_lock_release(lock) LeaveCriticalSection(lock)
#else /* !_WIN32 */
#include <pthread.h>
#define msh3_lock pthread_mutex_t
#define msh3_lock_initialize(lock) do { \
  pthread_mutexattr_t attr; \
  pthread_mutexattr_init(&attr); \
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); \
  pthread_mutex_init(lock, &attr); \
  pthread_mutexattr_destroy(&attr); \
}while(0)
#define msh3_lock_uninitialize(lock) pthread_mutex_destroy(lock)
#define msh3_lock_acquire(lock) pthread_mutex_lock(lock)
#define msh3_lock_release(lock) pthread_mutex_unlock(lock)
#endif /* _WIN32 */


static void MSH3_CALL msh3_conn_connected(MSH3_CONNECTION *Connection,
                                          void *IfContext);
static void MSH3_CALL msh3_conn_shutdown_complete(MSH3_CONNECTION *Connection,
                                          void *IfContext);
static void MSH3_CALL msh3_conn_new_request(MSH3_CONNECTION *Connection,
                                          void *IfContext,
                                          MSH3_REQUEST *Request);
static void MSH3_CALL msh3_header_received(MSH3_REQUEST *Request,
                                           void *IfContext,
                                           const MSH3_HEADER *Header);
static bool MSH3_CALL msh3_data_received(MSH3_REQUEST *Request,
                                        void *IfContext, uint32_t *Length,
                                        const uint8_t *Data);
static void MSH3_CALL msh3_complete(MSH3_REQUEST *Request, void *IfContext,
                                    bool Aborted, uint64_t AbortError);
static void MSH3_CALL msh3_shutdown_complete(MSH3_REQUEST *Request,
                                             void *IfContext);
static void MSH3_CALL msh3_data_sent(MSH3_REQUEST *Request,
                                     void *IfContext, void *SendContext);


void Curl_msh3_ver(char *p, size_t len)
{
  uint32_t v[4];
  MsH3Version(v);
  (void)msnprintf(p, len, "msh3/%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
}

#define SP_LOCAL   0
#define SP_REMOTE  1

struct cf_msh3_ctx {
  MSH3_API *api;
  MSH3_CONNECTION *qconn;
  struct Curl_sockaddr_ex addr;
  curl_socket_t sock[2]; /* fake socket pair until we get support in msh3 */
  char l_ip[MAX_IPADR_LEN];          /* local IP as string */
  int l_port;                        /* local port number */
  struct curltime connect_started;   /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  /* Flags written by msh3/msquic thread */
  bool handshake_complete;
  bool handshake_succeeded;
  bool connected;
  /* Flags written by curl thread */
  BIT(verbose);
  BIT(active);
};

static const MSH3_CONNECTION_IF msh3_conn_if = {
  msh3_conn_connected,
  msh3_conn_shutdown_complete,
  msh3_conn_new_request
};

static void MSH3_CALL msh3_conn_connected(MSH3_CONNECTION *Connection,
                                          void *IfContext)
{
  struct cf_msh3_ctx *ctx = IfContext;
  (void)Connection;
  if(ctx->verbose)
    CF_DEBUGF(fprintf(stderr, "* [MSH3] evt: connected\n"));
  ctx->handshake_succeeded = true;
  ctx->connected = true;
  ctx->handshake_complete = true;
}

static void MSH3_CALL msh3_conn_shutdown_complete(MSH3_CONNECTION *Connection,
                                          void *IfContext)
{
  struct cf_msh3_ctx *ctx = IfContext;
  (void)Connection;
  if(ctx->verbose)
    CF_DEBUGF(fprintf(stderr, "* [MSH3] evt: shutdown complete\n"));
  ctx->connected = false;
  ctx->handshake_complete = true;
}

static void MSH3_CALL msh3_conn_new_request(MSH3_CONNECTION *Connection,
                                          void *IfContext,
                                          MSH3_REQUEST *Request)
{
  (void)Connection;
  (void)IfContext;
  (void)Request;
}

static const MSH3_REQUEST_IF msh3_request_if = {
  msh3_header_received,
  msh3_data_received,
  msh3_complete,
  msh3_shutdown_complete,
  msh3_data_sent
};

static CURLcode msh3_data_setup(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;
  (void)cf;

  DEBUGASSERT(stream);
  if(!stream->recv_buf) {
    DEBUGF(LOG_CF(data, cf, "req: setup"));
    stream->recv_buf = malloc(MSH3_REQ_INIT_BUF_LEN);
    if(!stream->recv_buf) {
      return CURLE_OUT_OF_MEMORY;
    }
    stream->req = ZERO_NULL;
    msh3_lock_initialize(&stream->recv_lock);
    stream->recv_buf_alloc = MSH3_REQ_INIT_BUF_LEN;
    stream->recv_buf_max = MSH3_REQ_MAX_BUF_LEN;
    stream->recv_header_len = 0;
    stream->recv_header_complete = false;
    stream->recv_data_len = 0;
    stream->recv_data_complete = false;
    stream->recv_error = CURLE_OK;
  }
  return CURLE_OK;
}

/* Requires stream->recv_lock to be held */
static bool msh3request_ensure_room(struct HTTP *stream, size_t len)
{
  uint8_t *new_recv_buf;
  const size_t cur_recv_len = stream->recv_header_len + stream->recv_data_len;

  if(cur_recv_len + len > stream->recv_buf_alloc) {
    size_t new_recv_buf_alloc_len = stream->recv_buf_alloc;
    do {
      new_recv_buf_alloc_len <<= 1; /* TODO - handle overflow */
    } while(cur_recv_len + len > new_recv_buf_alloc_len);
    CF_DEBUGF(fprintf(stderr, "* enlarging buffer to %zu\n",
              new_recv_buf_alloc_len));
    new_recv_buf = malloc(new_recv_buf_alloc_len);
    if(!new_recv_buf) {
      CF_DEBUGF(fprintf(stderr, "* FAILED: enlarging buffer to %zu\n",
                new_recv_buf_alloc_len));
      return false;
    }
    if(cur_recv_len) {
      memcpy(new_recv_buf, stream->recv_buf, cur_recv_len);
    }
    stream->recv_buf_alloc = new_recv_buf_alloc_len;
    free(stream->recv_buf);
    stream->recv_buf = new_recv_buf;
  }
  return true;
}

static void MSH3_CALL msh3_header_received(MSH3_REQUEST *Request,
                                           void *IfContext,
                                           const MSH3_HEADER *Header)
{
  struct Curl_easy *data = IfContext;
  struct HTTP *stream = data->req.p.http;
  size_t total_len;
  (void)Request;

  if(stream->recv_header_complete) {
    CF_DEBUGF(fprintf(stderr, "* ignoring header after data\n"));
    return;
  }

  msh3_lock_acquire(&stream->recv_lock);

  if((Header->NameLength == 7) &&
     !strncmp(H2H3_PSEUDO_STATUS, (char *)Header->Name, 7)) {
    total_len = 10 + Header->ValueLength;
    if(!msh3request_ensure_room(stream, total_len)) {
      CF_DEBUGF(fprintf(stderr, "* ERROR: unable to buffer: %.*s\n",
                (int)Header->NameLength, Header->Name));
      stream->recv_error = CURLE_OUT_OF_MEMORY;
      goto release_lock;
    }
    msnprintf((char *)stream->recv_buf + stream->recv_header_len,
              stream->recv_buf_alloc - stream->recv_header_len,
              "HTTP/3 %.*s \r\n", (int)Header->ValueLength, Header->Value);
  }
  else {
    total_len = 4 + Header->NameLength + Header->ValueLength;
    if(!msh3request_ensure_room(stream, total_len)) {
      CF_DEBUGF(fprintf(stderr, "* ERROR: unable to buffer: %.*s\n",
                (int)Header->NameLength, Header->Name));
      stream->recv_error = CURLE_OUT_OF_MEMORY;
      goto release_lock;
    }
    msnprintf((char *)stream->recv_buf + stream->recv_header_len,
              stream->recv_buf_alloc - stream->recv_header_len,
              "%.*s: %.*s\r\n",
              (int)Header->NameLength, Header->Name,
              (int)Header->ValueLength, Header->Value);
  }

  stream->recv_header_len += total_len;
  data->state.drain = 1;

release_lock:
  msh3_lock_release(&stream->recv_lock);
}

static bool MSH3_CALL msh3_data_received(MSH3_REQUEST *Request,
                                         void *IfContext, uint32_t *Length,
                                         const uint8_t *Data)
{
  struct Curl_easy *data = IfContext;
  struct HTTP *stream = data->req.p.http;
  size_t cur_recv_len = stream->recv_header_len + stream->recv_data_len;

  (void)Request;
  if(data && data->set.verbose)
    CF_DEBUGF(fprintf(stderr, "* [MSH3] req: evt: received %u. %zu buffered, "
              "%zu allocated\n",
              *Length, cur_recv_len, stream->recv_buf_alloc));
  /* TODO - Update this code to limit data bufferring by `stream->recv_buf_max`
     and return `false` when we reach that limit. Then, when curl drains some
     of the buffer, making room, call MsH3RequestSetReceiveEnabled to enable
     receive callbacks again. */
  msh3_lock_acquire(&stream->recv_lock);

  if(!stream->recv_header_complete) {
    if(data && data->set.verbose)
      CF_DEBUGF(fprintf(stderr, "* [MSH3] req: Headers complete!\n"));
    if(!msh3request_ensure_room(stream, 2)) {
      stream->recv_error = CURLE_OUT_OF_MEMORY;
      goto release_lock;
    }
    stream->recv_buf[stream->recv_header_len++] = '\r';
    stream->recv_buf[stream->recv_header_len++] = '\n';
    stream->recv_header_complete = true;
    cur_recv_len += 2;
  }
  if(!msh3request_ensure_room(stream, *Length)) {
    stream->recv_error = CURLE_OUT_OF_MEMORY;
    goto release_lock;
  }
  memcpy(stream->recv_buf + cur_recv_len, Data, *Length);
  stream->recv_data_len += (size_t)*Length;
  data->state.drain = 1;

release_lock:
  msh3_lock_release(&stream->recv_lock);
  return true;
}

static void MSH3_CALL msh3_complete(MSH3_REQUEST *Request, void *IfContext,
                                    bool Aborted, uint64_t AbortError)
{
  struct Curl_easy *data = IfContext;
  struct HTTP *stream = data->req.p.http;

  (void)Request;
  (void)AbortError;
  if(data && data->set.verbose)
    CF_DEBUGF(fprintf(stderr, "* [MSH3] req: evt: complete, aborted=%s\n",
              Aborted ? "true" : "false"));
  msh3_lock_acquire(&stream->recv_lock);
  if(Aborted) {
    stream->recv_error = CURLE_HTTP3; /* TODO - how do we pass AbortError? */
  }
  stream->recv_header_complete = true;
  stream->recv_data_complete = true;
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_shutdown_complete(MSH3_REQUEST *Request,
                                             void *IfContext)
{
  struct Curl_easy *data = IfContext;
  struct HTTP *stream = data->req.p.http;
  (void)Request;
  (void)stream;
}

static void MSH3_CALL msh3_data_sent(MSH3_REQUEST *Request,
                                     void *IfContext, void *SendContext)
{
  struct Curl_easy *data = IfContext;
  struct HTTP *stream = data->req.p.http;
  (void)Request;
  (void)stream;
  (void)SendContext;
}

static ssize_t cf_msh3_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                            char *buf, size_t len, CURLcode *err)
{
  struct HTTP *stream = data->req.p.http;
  size_t outsize = 0;

  (void)cf;
  DEBUGF(LOG_CF(data, cf, "req: recv with %zu byte buffer", len));

  if(stream->recv_error) {
    failf(data, "request aborted");
    data->state.drain = 0;
    *err = stream->recv_error;
    return -1;
  }

  *err = CURLE_OK;
  msh3_lock_acquire(&stream->recv_lock);

  if(stream->recv_header_len) {
    outsize = len;
    if(stream->recv_header_len < outsize) {
      outsize = stream->recv_header_len;
    }
    memcpy(buf, stream->recv_buf, outsize);
    if(outsize < stream->recv_header_len + stream->recv_data_len) {
      memmove(stream->recv_buf, stream->recv_buf + outsize,
              stream->recv_header_len + stream->recv_data_len - outsize);
    }
    stream->recv_header_len -= outsize;
    DEBUGF(LOG_CF(data, cf, "req: returned %zu bytes of header", outsize));
  }
  else if(stream->recv_data_len) {
    outsize = len;
    if(stream->recv_data_len < outsize) {
      outsize = stream->recv_data_len;
    }
    memcpy(buf, stream->recv_buf, outsize);
    if(outsize < stream->recv_data_len) {
      memmove(stream->recv_buf, stream->recv_buf + outsize,
              stream->recv_data_len - outsize);
    }
    stream->recv_data_len -= outsize;
    DEBUGF(LOG_CF(data, cf, "req: returned %zu bytes of data", outsize));
    if(stream->recv_data_len == 0 && stream->recv_data_complete)
      data->state.drain = 1;
  }
  else if(stream->recv_data_complete) {
    DEBUGF(LOG_CF(data, cf, "req: receive complete"));
    data->state.drain = 0;
  }
  else {
    DEBUGF(LOG_CF(data, cf, "req: nothing here, call again"));
    *err = CURLE_AGAIN;
    outsize = -1;
  }

  msh3_lock_release(&stream->recv_lock);

  return (ssize_t)outsize;
}

static ssize_t cf_msh3_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                            const void *buf, size_t len, CURLcode *err)
{
  struct cf_msh3_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  struct h2h3req *hreq;
  size_t hdrlen = 0;
  size_t sentlen = 0;

  /* Sizes must match for cast below to work" */
  DEBUGASSERT(sizeof(MSH3_HEADER) == sizeof(struct h2h3pseudo));
  DEBUGF(LOG_CF(data, cf, "req: send %zu bytes", len));

  if(!stream->req) {
    /* The first send on the request contains the headers and possibly some
       data. Parse out the headers and create the request, then if there is
       any data left over go ahead and send it too. */

    *err = msh3_data_setup(cf, data);
    if(*err) {
      failf(data, "could not setup data");
      return -1;
    }

    *err = Curl_pseudo_headers(data, buf, len, &hdrlen, &hreq);
    if(*err) {
      failf(data, "Curl_pseudo_headers failed");
      return -1;
    }

    DEBUGF(LOG_CF(data, cf, "req: send %zu headers", hreq->entries));
    stream->req = MsH3RequestOpen(ctx->qconn, &msh3_request_if, data,
                                  (MSH3_HEADER*)hreq->header, hreq->entries,
                                  hdrlen == len ? MSH3_REQUEST_FLAG_FIN :
                                  MSH3_REQUEST_FLAG_NONE);
    Curl_pseudo_free(hreq);
    if(!stream->req) {
      failf(data, "request open failed");
      *err = CURLE_SEND_ERROR;
      return -1;
    }
    *err = CURLE_OK;
    return len;
  }

  DEBUGF(LOG_CF(data, cf, "req: send %zd body bytes", len));
  if(len > 0xFFFFFFFF) {
    /* msh3 doesn't support size_t sends currently. */
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  /* TODO - Need an explicit signal to know when to FIN. */
  if(!MsH3RequestSend(stream->req, MSH3_REQUEST_FLAG_FIN, buf, (uint32_t)len,
                      stream)) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  /* TODO - msh3/msquic will hold onto this memory until the send complete
     event. How do we make sure curl doesn't free it until then? */
  sentlen += len;
  *err = CURLE_OK;
  return sentlen;
}

static int cf_msh3_get_select_socks(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    curl_socket_t *socks)
{
  struct cf_msh3_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  int bitmap = GETSOCK_BLANK;

  if(stream && ctx->sock[SP_LOCAL] != CURL_SOCKET_BAD) {
    socks[0] = ctx->sock[SP_LOCAL];

    if(stream->recv_error) {
      bitmap |= GETSOCK_READSOCK(0);
      data->state.drain = 1;
    }
    else if(stream->recv_header_len || stream->recv_data_len) {
      bitmap |= GETSOCK_READSOCK(0);
      data->state.drain = 1;
    }
  }
  DEBUGF(LOG_CF(data, cf, "select_sock %u -> %d",
                (uint32_t)data->state.drain, bitmap));

  return bitmap;
}

static bool cf_msh3_data_pending(struct Curl_cfilter *cf,
                                 const struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;

  (void)cf;
  DEBUGF(LOG_CF((struct Curl_easy *)data, cf, "data pending = %hhu",
                (bool)(stream->recv_header_len || stream->recv_data_len)));
  return stream->recv_header_len || stream->recv_data_len;
}

static void cf_msh3_active(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_msh3_ctx *ctx = cf->ctx;

  /* use this socket from now on */
  cf->conn->sock[cf->sockindex] = ctx->sock[SP_LOCAL];
  /* the first socket info gets set at conn and data */
  if(cf->sockindex == FIRSTSOCKET) {
    cf->conn->remote_addr = &ctx->addr;
  #ifdef ENABLE_IPV6
    cf->conn->bits.ipv6 = (ctx->addr.family == AF_INET6)? TRUE : FALSE;
  #endif
    Curl_persistconninfo(data, cf->conn, ctx->l_ip, ctx->l_port);
  }
  ctx->active = TRUE;
}

static CURLcode cf_msh3_data_event(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   int event, int arg1, void *arg2)
{
  struct cf_msh3_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    result = msh3_data_setup(cf, data);
    break;
  case CF_CTRL_DATA_DONE:
    DEBUGF(LOG_CF(data, cf, "req: done"));
    if(stream) {
      if(stream->recv_buf) {
        Curl_safefree(stream->recv_buf);
        msh3_lock_uninitialize(&stream->recv_lock);
      }
      if(stream->req) {
        MsH3RequestClose(stream->req);
        stream->req = ZERO_NULL;
      }
    }
    break;
  case CF_CTRL_DATA_DONE_SEND:
    DEBUGF(LOG_CF(data, cf, "req: send done"));
    stream->upload_done = TRUE;
    break;
  case CF_CTRL_CONN_INFO_UPDATE:
    DEBUGF(LOG_CF(data, cf, "req: update info"));
    cf_msh3_active(cf, data);
    break;
  case CF_CTRL_CONN_REPORT_STATS:
    if(cf->sockindex == FIRSTSOCKET)
      Curl_pgrsTimeWas(data, TIMER_APPCONNECT, ctx->handshake_at);
    break;

  default:
    break;
  }
  return result;
}

static CURLcode cf_connect_start(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  struct cf_msh3_ctx *ctx = cf->ctx;
  bool verify = !!cf->conn->ssl_config.verifypeer;
  MSH3_ADDR addr = {0};
  memcpy(&addr, &ctx->addr.sa_addr, ctx->addr.addrlen);
  MSH3_SET_PORT(&addr, (uint16_t)cf->conn->remote_port);
  ctx->verbose = (data && data->set.verbose);

  if(verify && (cf->conn->ssl_config.CAfile || cf->conn->ssl_config.CApath)) {
    /* TODO: need a way to provide trust anchors to MSH3 */
#ifdef DEBUGBUILD
    /* we need this for our test cases to run */
    DEBUGF(LOG_CF(data, cf, "non-standard CA not supported, "
                  "switching off verifypeer in DEBUG mode"));
    verify = 0;
#else
    DEBUGF(LOG_CF(data, cf, "non-standard CA not supported, "
                  "attempting with built-in verification"));
#endif
  }

  DEBUGF(LOG_CF(data, cf, "connecting to %s:%d (verify=%d)",
                cf->conn->host.name, (int)cf->conn->remote_port, verify));

  ctx->api = MsH3ApiOpen();
  if(!ctx->api) {
    failf(data, "can't create msh3 api");
    return CURLE_FAILED_INIT;
  }

  ctx->qconn = MsH3ConnectionOpen(ctx->api,
                                  &msh3_conn_if,
                                  ctx,
                                  cf->conn->host.name,
                                  &addr,
                                  !verify);
  if(!ctx->qconn) {
    failf(data, "can't create msh3 connection");
    if(ctx->api) {
      MsH3ApiClose(ctx->api);
      ctx->api = NULL;
    }
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static CURLcode cf_msh3_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool blocking, bool *done)
{
  struct cf_msh3_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ctx->sock[SP_LOCAL] == CURL_SOCKET_BAD) {
    if(Curl_socketpair(AF_UNIX, SOCK_STREAM, 0, &ctx->sock[0]) < 0) {
      ctx->sock[SP_LOCAL] = CURL_SOCKET_BAD;
      ctx->sock[SP_REMOTE] = CURL_SOCKET_BAD;
      return CURLE_COULDNT_CONNECT;
    }
  }

  *done = FALSE;
  if(!ctx->qconn) {
    ctx->connect_started = Curl_now();
    result = cf_connect_start(cf, data);
    if(result)
      goto out;
  }

  if(ctx->handshake_complete) {
    ctx->handshake_at = Curl_now();
    if(ctx->handshake_succeeded) {
      cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
      cf->conn->httpversion = 30;
      cf->conn->bundle->multiuse = BUNDLE_MULTIPLEX;
      cf->connected = TRUE;
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
      Curl_pgrsTime(data, TIMER_APPCONNECT);
    }
    else {
      failf(data, "failed to connect, handshake failed");
      result = CURLE_COULDNT_CONNECT;
    }
  }

out:
  return result;
}

static void cf_msh3_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_msh3_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    DEBUGF(LOG_CF(data, cf, "destroying"));
    if(ctx->qconn)
      MsH3ConnectionClose(ctx->qconn);
    if(ctx->api)
      MsH3ApiClose(ctx->api);

    if(ctx->active) {
      /* We share our socket at cf->conn->sock[cf->sockindex] when active.
       * If it is no longer there, someone has stolen (and hopefully
       * closed it) and we just forget about it.
       */
      if(ctx->sock[SP_LOCAL] == cf->conn->sock[cf->sockindex]) {
        DEBUGF(LOG_CF(data, cf, "cf_msh3_close(%d) active",
                      (int)ctx->sock[SP_LOCAL]));
        cf->conn->sock[cf->sockindex] = CURL_SOCKET_BAD;
      }
      else {
        DEBUGF(LOG_CF(data, cf, "cf_socket_close(%d) no longer at "
                      "conn->sock[], discarding", (int)ctx->sock[SP_LOCAL]));
        ctx->sock[SP_LOCAL] = CURL_SOCKET_BAD;
      }
      if(cf->sockindex == FIRSTSOCKET)
        cf->conn->remote_addr = NULL;
    }
    if(ctx->sock[SP_LOCAL] != CURL_SOCKET_BAD) {
      sclose(ctx->sock[SP_LOCAL]);
    }
    if(ctx->sock[SP_REMOTE] != CURL_SOCKET_BAD) {
      sclose(ctx->sock[SP_REMOTE]);
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->sock[SP_LOCAL] = CURL_SOCKET_BAD;
    ctx->sock[SP_REMOTE] = CURL_SOCKET_BAD;
  }
}

static void cf_msh3_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  cf_msh3_close(cf, data);
  free(cf->ctx);
  cf->ctx = NULL;
}

static CURLcode cf_msh3_query(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              int query, int *pres1, void *pres2)
{
  struct cf_msh3_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    /* TODO: we do not have access to this so far, fake it */
    (void)ctx;
    *pres1 = 100;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_msh3_conn_is_alive(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_msh3_ctx *ctx = cf->ctx;

  (void)data;
  return ctx && ctx->sock[SP_LOCAL] != CURL_SOCKET_BAD && ctx->qconn &&
         ctx->connected;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX,
  0,
  cf_msh3_destroy,
  cf_msh3_connect,
  cf_msh3_close,
  Curl_cf_def_get_host,
  cf_msh3_get_select_socks,
  cf_msh3_data_pending,
  cf_msh3_send,
  cf_msh3_recv,
  cf_msh3_data_event,
  cf_msh3_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_msh3_query,
};

CURLcode Curl_cf_msh3_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             const struct Curl_addrinfo *ai)
{
  struct cf_msh3_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  (void)ai; /* TODO: msh3 resolves itself? */
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  Curl_sock_assign_addr(&ctx->addr, ai, TRNSPRT_QUIC);
  ctx->sock[SP_LOCAL] = CURL_SOCKET_BAD;
  ctx->sock[SP_REMOTE] = CURL_SOCKET_BAD;

  result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);

out:
  *pcf = (!result)? cf : NULL;
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }

  return result;
}

bool Curl_conn_is_msh3(const struct Curl_easy *data,
                       const struct connectdata *conn,
                       int sockindex)
{
  struct Curl_cfilter *cf = conn? conn->cfilter[sockindex] : NULL;

  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_http3)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

#endif /* USE_MSH3 */
