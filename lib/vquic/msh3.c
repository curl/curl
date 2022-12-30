/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "cfilters.h"
#include "connect.h"
#include "h2h3.h"
#include "msh3.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* #define DEBUG_HTTP3 1 */
#ifdef DEBUG_HTTP3
#define H3BUGF(x) x
#else
#define H3BUGF(x) do { } while(0)
#endif

#define MSH3_REQ_INIT_BUF_LEN 8192

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


static void MSH3_CALL msh3_header_received(MSH3_REQUEST *Request,
                                           void *IfContext,
                                           const MSH3_HEADER *Header);
static void MSH3_CALL msh3_data_received(MSH3_REQUEST *Request,
                                        void *IfContext, uint32_t Length,
                                        const uint8_t *Data);
static void MSH3_CALL msh3_complete(MSH3_REQUEST *Request, void *IfContext,
                                    bool Aborted, uint64_t AbortError);
static void MSH3_CALL msh3_shutdown(MSH3_REQUEST *Request, void *IfContext);
static void MSH3_CALL msh3_send_complete(MSH3_REQUEST *Request,
                                         void *IfContext, void *SendContext);


void Curl_msh3_ver(char *p, size_t len)
{
  uint32_t v[4];
  MsH3Version(v);
  (void)msnprintf(p, len, "msh3/%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
}

struct cf_msh3_ctx {
  MSH3_API *api;
  MSH3_CONNECTION *qconn;
};

static const MSH3_REQUEST_IF msh3_request_if = {
  msh3_header_received,
  msh3_data_received,
  msh3_complete,
  msh3_shutdown,
  msh3_send_complete
};

static CURLcode msh3_data_setup(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;
  (void)cf;

  H3BUGF(infof(data, "msh3_data_setup"));
  stream->recv_buf = malloc(MSH3_REQ_INIT_BUF_LEN);
  if(!stream->recv_buf) {
    return CURLE_OUT_OF_MEMORY;
  }
  stream->req = ZERO_NULL;
  msh3_lock_initialize(&stream->recv_lock);
  stream->recv_buf_alloc = MSH3_REQ_INIT_BUF_LEN;
  stream->recv_header_len = 0;
  stream->recv_header_complete = false;
  stream->recv_data_len = 0;
  stream->recv_data_complete = false;
  stream->recv_error = CURLE_OK;
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
    new_recv_buf = malloc(new_recv_buf_alloc_len);
    if(!new_recv_buf) {
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
  struct HTTP *stream = IfContext;
  size_t total_len;
  (void)Request;

  if(stream->recv_header_complete) {
    H3BUGF(printf("* ignoring header after data\n"));
    return;
  }

  msh3_lock_acquire(&stream->recv_lock);

  if((Header->NameLength == 7) &&
     !strncmp(H2H3_PSEUDO_STATUS, (char *)Header->Name, 7)) {
     total_len = 9 + Header->ValueLength;
    if(!msh3request_ensure_room(stream, total_len)) {
      /* TODO - handle error */
      goto release_lock;
    }
    msnprintf((char *)stream->recv_buf + stream->recv_header_len,
              stream->recv_buf_alloc - stream->recv_header_len,
              "HTTP/3 %.*s \r\n", (int)Header->ValueLength, Header->Value);
  }
  else {
    total_len = Header->NameLength + 4 + Header->ValueLength;
    if(!msh3request_ensure_room(stream, total_len)) {
      /* TODO - handle error */
      goto release_lock;
    }
    msnprintf((char *)stream->recv_buf + stream->recv_header_len,
              stream->recv_buf_alloc - stream->recv_header_len,
              "%.*s: %.*s\r\n",
              (int)Header->NameLength, Header->Name,
              (int)Header->ValueLength, Header->Value);
  }

  stream->recv_header_len += total_len - 1; /* don't include null-terminator */

release_lock:
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_data_received(MSH3_REQUEST *Request,
                                         void *IfContext, uint32_t Length,
                                         const uint8_t *Data)
{
  struct HTTP *stream = IfContext;
  size_t cur_recv_len = stream->recv_header_len + stream->recv_data_len;
  (void)Request;
  H3BUGF(printf("* msh3_data_received %u. %zu buffered, %zu allocated\n",
                Length, cur_recv_len, stream->recv_buf_alloc));
  msh3_lock_acquire(&stream->recv_lock);
  if(!stream->recv_header_complete) {
    H3BUGF(printf("* Headers complete!\n"));
    if(!msh3request_ensure_room(stream, 2)) {
      /* TODO - handle error */
      goto release_lock;
    }
    stream->recv_buf[stream->recv_header_len++] = '\r';
    stream->recv_buf[stream->recv_header_len++] = '\n';
    stream->recv_header_complete = true;
    cur_recv_len += 2;
  }
  if(!msh3request_ensure_room(stream, Length)) {
    /* TODO - handle error */
    goto release_lock;
  }
  memcpy(stream->recv_buf + cur_recv_len, Data, Length);
  stream->recv_data_len += (size_t)Length;
release_lock:
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_complete(MSH3_REQUEST *Request, void *IfContext,
                                    bool Aborted, uint64_t AbortError)
{
  struct HTTP *stream = IfContext;
  (void)Request;
  (void)AbortError;
  H3BUGF(printf("* msh3_complete, aborted=%s\n", Aborted ? "true" : "false"));
  msh3_lock_acquire(&stream->recv_lock);
  if(Aborted) {
    stream->recv_error = CURLE_HTTP3; /* TODO - how do we pass AbortError? */
  }
  stream->recv_header_complete = true;
  stream->recv_data_complete = true;
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_shutdown(MSH3_REQUEST *Request, void *IfContext)
{
  struct HTTP *stream = IfContext;
  (void)Request;
  (void)stream;
}

static void MSH3_CALL msh3_send_complete(MSH3_REQUEST *Request,
                                         void *IfContext, void *SendContext)
{
  struct HTTP *stream = IfContext;
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
  H3BUGF(infof(data, "msh3_stream_recv %zu", len));

  if(stream->recv_error) {
    failf(data, "request aborted");
    *err = stream->recv_error;
    return -1;
  }

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
    H3BUGF(infof(data, "returned %zu bytes of headers", outsize));
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
    H3BUGF(infof(data, "returned %zu bytes of data", outsize));
  }
  else if(stream->recv_data_complete) {
    H3BUGF(infof(data, "receive complete"));
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

  H3BUGF(infof(data, "msh3_stream_send %zu", len));

  if(!stream->req) {
    /* The first send on the request contains the headers and possibly some
       data. Parse out the headers and create the request, then if there is
       any data left over go ahead and send it too. */
    *err = Curl_pseudo_headers(data, buf, len, &hdrlen, &hreq);
    if(*err) {
      failf(data, "Curl_pseudo_headers failed");
      return -1;
    }

    H3BUGF(infof(data, "starting request with %zu headers", hreq->entries));
    stream->req = MsH3RequestOpen(ctx->qconn, &msh3_request_if, stream,
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
  H3BUGF(infof(data, "send %zd body bytes on request %p", len,
               (void *)stream->req));
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
  struct HTTP *stream = data->req.p.http;
  int bitmap = GETSOCK_BLANK;

  socks[0] = cf->conn->sock[FIRSTSOCKET];

  if(stream->recv_error) {
    bitmap |= GETSOCK_READSOCK(0);
    data->state.drain++;
  }
  else if(stream->recv_header_len || stream->recv_data_len) {
    bitmap |= GETSOCK_READSOCK(0);
    data->state.drain++;
  }
  H3BUGF(infof(data, "msh3_getsock %u", (uint32_t)data->state.drain));

  return bitmap;
}

static bool cf_msh3_data_pending(struct Curl_cfilter *cf,
                                 const struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;

  (void)data;
  (void)cf;
  H3BUGF(infof((struct Curl_easy *)data, "Curl_quic_data_pending"));
  return stream->recv_header_len || stream->recv_data_len;
}

static CURLcode cf_msh3_data_event(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   int event, int arg1, void *arg2)
{
  struct HTTP *stream = data->req.p.http;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    result = msh3_data_setup(cf, data);
    break;

  case CF_CTRL_DATA_DONE:
    H3BUGF(infof(data, "Curl_quic_done"));
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
    H3BUGF(infof(data, "Curl_quic_done_sending"));
    stream->upload_done = TRUE;
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
  bool insecure = !cf->conn->ssl_config.verifypeer;

  H3BUGF(infof(data, "creating new api/connection"));

  ctx->api = MsH3ApiOpen();
  if(!ctx->api) {
    failf(data, "can't create msh3 api");
    return CURLE_FAILED_INIT;
  }

  ctx->qconn = MsH3ConnectionOpen(ctx->api,
                                  cf->conn->host.name,
                                  (uint16_t)cf->conn->remote_port,
                                  insecure);
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
  MSH3_CONNECTION_STATE state;
  CURLcode result = CURLE_OK;

  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  if(!ctx->qconn) {
    result = cf_connect_start(cf, data);
    if(result)
      goto out;
  }

  state = MsH3ConnectionGetState(ctx->qconn, FALSE);
  if(state == MSH3_CONN_HANDSHAKE_FAILED || state == MSH3_CONN_DISCONNECTED) {
    failf(data, "failed to connect, state=%u", (uint32_t)state);
    result = CURLE_COULDNT_CONNECT;
    goto out;
  }

  if(state == MSH3_CONN_CONNECTED) {
    DEBUGF(infof(data, "msh3 established connection"));
    cf->connected = TRUE;
    cf->conn->alpn = CURL_HTTP_VERSION_3;
    *done = TRUE;
    connkeep(cf->conn, "HTTP/3 default");
  }

out:
  return result;
}

static void cf_msh3_ctx_clear(struct cf_msh3_ctx *ctx)
{
  if(ctx) {
    if(ctx->qconn)
      MsH3ConnectionClose(ctx->qconn);
    if(ctx->api)
      MsH3ApiClose(ctx->api);
    memset(ctx, 0, sizeof(*ctx));
  }
}

static void cf_msh3_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_msh3_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    cf_msh3_ctx_clear(ctx);
  }
}

static void cf_msh3_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_msh3_ctx *ctx = cf->ctx;

  (void)data;
  cf_msh3_ctx_clear(ctx);
  free(ctx);
  cf->ctx = NULL;
}

static const struct Curl_cftype cft_msh3 = {
  "HTTP/3-MSH3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX,
  cf_msh3_destroy,
  cf_msh3_connect,
  cf_msh3_close,
  Curl_cf_def_get_host,
  cf_msh3_get_select_socks,
  cf_msh3_data_pending,
  cf_msh3_send,
  cf_msh3_recv,
  cf_msh3_data_event,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
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

  result = Curl_cf_create(&cf, &cft_msh3, ctx);

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
    if(cf->cft == &cft_msh3)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

#endif /* USE_MSH3 */
