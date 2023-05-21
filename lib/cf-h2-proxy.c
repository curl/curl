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

#if defined(USE_NGHTTP2) && !defined(CURL_DISABLE_PROXY)

#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "cfilters.h"
#include "connect.h"
#include "curl_log.h"
#include "bufq.h"
#include "dynbuf.h"
#include "dynhds.h"
#include "http1.h"
#include "http_proxy.h"
#include "multiif.h"
#include "cf-h2-proxy.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define H2_NW_CHUNK_SIZE  (128*1024)
#define H2_NW_RECV_CHUNKS   1
#define H2_NW_SEND_CHUNKS   1

#define HTTP2_HUGE_WINDOW_SIZE (32 * 1024 * 1024) /* 32 MB */

#define H2_TUNNEL_WINDOW_SIZE (1024 * 1024)
#define H2_TUNNEL_CHUNK_SIZE   (32 * 1024)
#define H2_TUNNEL_RECV_CHUNKS \
          (H2_TUNNEL_WINDOW_SIZE / H2_TUNNEL_CHUNK_SIZE)
#define H2_TUNNEL_SEND_CHUNKS \
          (H2_TUNNEL_WINDOW_SIZE / H2_TUNNEL_CHUNK_SIZE)

typedef enum {
    TUNNEL_INIT,     /* init/default/no tunnel state */
    TUNNEL_CONNECT,  /* CONNECT request is being send */
    TUNNEL_RESPONSE, /* CONNECT response received completely */
    TUNNEL_ESTABLISHED,
    TUNNEL_FAILED
} tunnel_state;

struct tunnel_stream {
  struct http_resp *resp;
  struct bufq recvbuf;
  struct bufq sendbuf;
  char *authority;
  int32_t stream_id;
  uint32_t error;
  tunnel_state state;
  bool has_final_response;
  bool closed;
  bool reset;
};

static CURLcode tunnel_stream_init(struct Curl_cfilter *cf,
                                    struct tunnel_stream *ts)
{
  const char *hostname;
  int port;
  bool ipv6_ip = cf->conn->bits.ipv6_ip;

  ts->state = TUNNEL_INIT;
  ts->stream_id = -1;
  Curl_bufq_init2(&ts->recvbuf, H2_TUNNEL_CHUNK_SIZE, H2_TUNNEL_RECV_CHUNKS,
                  BUFQ_OPT_SOFT_LIMIT);
  Curl_bufq_init(&ts->sendbuf, H2_TUNNEL_CHUNK_SIZE, H2_TUNNEL_SEND_CHUNKS);

  if(cf->conn->bits.conn_to_host)
    hostname = cf->conn->conn_to_host.name;
  else if(cf->sockindex == SECONDARYSOCKET)
    hostname = cf->conn->secondaryhostname;
  else
    hostname = cf->conn->host.name;

  if(cf->sockindex == SECONDARYSOCKET)
    port = cf->conn->secondary_port;
  else if(cf->conn->bits.conn_to_port)
    port = cf->conn->conn_to_port;
  else
    port = cf->conn->remote_port;

  if(hostname != cf->conn->host.name)
    ipv6_ip = (strchr(hostname, ':') != NULL);

  ts->authority = /* host:port with IPv6 support */
    aprintf("%s%s%s:%d", ipv6_ip?"[":"", hostname, ipv6_ip?"]":"", port);
  if(!ts->authority)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static void tunnel_stream_clear(struct tunnel_stream *ts)
{
  Curl_http_resp_free(ts->resp);
  Curl_bufq_free(&ts->recvbuf);
  Curl_bufq_free(&ts->sendbuf);
  Curl_safefree(ts->authority);
  memset(ts, 0, sizeof(*ts));
  ts->state = TUNNEL_INIT;
}

static void tunnel_go_state(struct Curl_cfilter *cf,
                            struct tunnel_stream *ts,
                            tunnel_state new_state,
                            struct Curl_easy *data)
{
  (void)cf;

  if(ts->state == new_state)
    return;
  /* leaving this one */
  switch(ts->state) {
  case TUNNEL_CONNECT:
    data->req.ignorebody = FALSE;
    break;
  default:
    break;
  }
  /* entering this one */
  switch(new_state) {
  case TUNNEL_INIT:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'init'"));
    tunnel_stream_clear(ts);
    break;

  case TUNNEL_CONNECT:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'connect'"));
    ts->state = TUNNEL_CONNECT;
    break;

  case TUNNEL_RESPONSE:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'response'"));
    ts->state = TUNNEL_RESPONSE;
    break;

  case TUNNEL_ESTABLISHED:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'established'"));
    infof(data, "CONNECT phase completed");
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    /* FALLTHROUGH */
  case TUNNEL_FAILED:
    if(new_state == TUNNEL_FAILED)
      DEBUGF(LOG_CF(data, cf, "new tunnel state 'failed'"));
    ts->state = new_state;
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it isn't accidentally used for the document request
       after we've connected. So let's free and clear it here. */
    Curl_safefree(data->state.aptr.proxyuserpwd);
    break;
  }
}

struct cf_h2_proxy_ctx {
  nghttp2_session *h2;
  /* The easy handle used in the current filter call, cleared at return */
  struct cf_call_data call_data;

  struct bufq inbufq;  /* network receive buffer */
  struct bufq outbufq; /* network send buffer */

  struct tunnel_stream tunnel; /* our tunnel CONNECT stream */
  int32_t goaway_error;
  int32_t last_stream_id;
  BIT(conn_closed);
  BIT(goaway);
};

/* How to access `call_data` from a cf_h2 filter */
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_h2_proxy_ctx *)(cf)->ctx)->call_data

static void cf_h2_proxy_ctx_clear(struct cf_h2_proxy_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(ctx->h2) {
    nghttp2_session_del(ctx->h2);
  }
  Curl_bufq_free(&ctx->inbufq);
  Curl_bufq_free(&ctx->outbufq);
  tunnel_stream_clear(&ctx->tunnel);
  memset(ctx, 0, sizeof(*ctx));
  ctx->call_data = save;
}

static void cf_h2_proxy_ctx_free(struct cf_h2_proxy_ctx *ctx)
{
  if(ctx) {
    cf_h2_proxy_ctx_clear(ctx);
    free(ctx);
  }
}

static ssize_t nw_in_reader(void *reader_ctx,
                              unsigned char *buf, size_t buflen,
                              CURLcode *err)
{
  struct Curl_cfilter *cf = reader_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nread;

  nread = Curl_conn_cf_recv(cf->next, data, (char *)buf, buflen, err);
  DEBUGF(LOG_CF(data, cf, "nw_in recv(len=%zu) -> %zd, %d",
         buflen, nread, *err));
  return nread;
}

static ssize_t nw_out_writer(void *writer_ctx,
                             const unsigned char *buf, size_t buflen,
                             CURLcode *err)
{
  struct Curl_cfilter *cf = writer_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;

  nwritten = Curl_conn_cf_send(cf->next, data, (const char *)buf, buflen, err);
  DEBUGF(LOG_CF(data, cf, "nw_out send(len=%zu) -> %zd", buflen, nwritten));
  return nwritten;
}

static int h2_client_new(struct Curl_cfilter *cf,
                         nghttp2_session_callbacks *cbs)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  nghttp2_option *o;

  int rc = nghttp2_option_new(&o);
  if(rc)
    return rc;
  /* We handle window updates ourself to enforce buffer limits */
  nghttp2_option_set_no_auto_window_update(o, 1);
#if NGHTTP2_VERSION_NUM >= 0x013200
  /* with 1.50.0 */
  /* turn off RFC 9113 leading and trailing white spaces validation against
     HTTP field value. */
  nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(o, 1);
#endif
  rc = nghttp2_session_client_new2(&ctx->h2, cbs, cf, o);
  nghttp2_option_del(o);
  return rc;
}

static ssize_t on_session_send(nghttp2_session *h2,
                              const uint8_t *buf, size_t blen,
                              int flags, void *userp);
static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp);
static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp);
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp);
static int tunnel_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id,
                                const uint8_t *mem, size_t len, void *userp);

/*
 * Initialize the cfilter context
 */
static CURLcode cf_h2_proxy_ctx_init(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  nghttp2_session_callbacks *cbs = NULL;
  int rc;

  DEBUGASSERT(!ctx->h2);
  memset(&ctx->tunnel, 0, sizeof(ctx->tunnel));

  Curl_bufq_init(&ctx->inbufq, H2_NW_CHUNK_SIZE, H2_NW_RECV_CHUNKS);
  Curl_bufq_init(&ctx->outbufq, H2_NW_CHUNK_SIZE, H2_NW_SEND_CHUNKS);

  if(tunnel_stream_init(cf, &ctx->tunnel))
    goto out;

  rc = nghttp2_session_callbacks_new(&cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2 callbacks");
    goto out;
  }

  nghttp2_session_callbacks_set_send_callback(cbs, on_session_send);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    cbs, tunnel_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);
  nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);

  /* The nghttp2 session is not yet setup, do it */
  rc = h2_client_new(cf, cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2");
    goto out;
  }

  {
    nghttp2_settings_entry iv[3];

    iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    iv[0].value = Curl_multi_max_concurrent_streams(data->multi);
    iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
    iv[1].value = H2_TUNNEL_WINDOW_SIZE;
    iv[2].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
    iv[2].value = 0;
    rc = nghttp2_submit_settings(ctx->h2, NGHTTP2_FLAG_NONE, iv, 3);
    if(rc) {
      failf(data, "nghttp2_submit_settings() failed: %s(%d)",
            nghttp2_strerror(rc), rc);
      result = CURLE_HTTP2;
      goto out;
    }
  }

  rc = nghttp2_session_set_local_window_size(ctx->h2, NGHTTP2_FLAG_NONE, 0,
                                             HTTP2_HUGE_WINDOW_SIZE);
  if(rc) {
    failf(data, "nghttp2_session_set_local_window_size() failed: %s(%d)",
          nghttp2_strerror(rc), rc);
    result = CURLE_HTTP2;
    goto out;
  }


  /* all set, traffic will be send on connect */
  result = CURLE_OK;

out:
  if(cbs)
    nghttp2_session_callbacks_del(cbs);
  DEBUGF(LOG_CF(data, cf, "init proxy ctx -> %d", result));
  return result;
}

static CURLcode nw_out_flush(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  size_t buflen = Curl_bufq_len(&ctx->outbufq);
  ssize_t nwritten;
  CURLcode result;

  (void)data;
  if(!buflen)
    return CURLE_OK;

  DEBUGF(LOG_CF(data, cf, "h2 conn flush %zu bytes", buflen));
  nwritten = Curl_bufq_pass(&ctx->outbufq, nw_out_writer, cf, &result);
  if(nwritten < 0) {
    return result;
  }
  if((size_t)nwritten < buflen) {
    return CURLE_AGAIN;
  }
  return CURLE_OK;
}

/*
 * Processes pending input left in network input buffer.
 * This function returns 0 if it succeeds, or -1 and error code will
 * be assigned to *err.
 */
static int h2_process_pending_input(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  const unsigned char *buf;
  size_t blen;
  ssize_t rv;

  while(Curl_bufq_peek(&ctx->inbufq, &buf, &blen)) {

    rv = nghttp2_session_mem_recv(ctx->h2, (const uint8_t *)buf, blen);
    DEBUGF(LOG_CF(data, cf,
                 "fed %zu bytes from nw to nghttp2 -> %zd", blen, rv));
    if(rv < 0) {
      failf(data,
            "process_pending_input: nghttp2_session_mem_recv() returned "
            "%zd:%s", rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
      return -1;
    }
    Curl_bufq_skip(&ctx->inbufq, (size_t)rv);
    if(Curl_bufq_is_empty(&ctx->inbufq)) {
      DEBUGF(LOG_CF(data, cf, "all data in connection buffer processed"));
      break;
    }
    else {
      DEBUGF(LOG_CF(data, cf, "process_pending_input: %zu bytes left "
                    "in connection buffer", Curl_bufq_len(&ctx->inbufq)));
    }
  }

  if(nghttp2_session_check_request_allowed(ctx->h2) == 0) {
    /* No more requests are allowed in the current session, so
       the connection may not be reused. This is set when a
       GOAWAY frame has been received or when the limit of stream
       identifiers has been reached. */
    connclose(cf->conn, "http/2: No new requests allowed");
  }

  return 0;
}

static CURLcode h2_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  ssize_t nread;

  /* Process network input buffer fist */
  if(!Curl_bufq_is_empty(&ctx->inbufq)) {
    DEBUGF(LOG_CF(data, cf, "Process %zd bytes in connection buffer",
                  Curl_bufq_len(&ctx->inbufq)));
    if(h2_process_pending_input(cf, data, &result) < 0)
      return result;
  }

  /* Receive data from the "lower" filters, e.g. network until
   * it is time to stop or we have enough data for this stream */
  while(!ctx->conn_closed &&               /* not closed the connection */
        !ctx->tunnel.closed &&             /* nor the tunnel */
        Curl_bufq_is_empty(&ctx->inbufq) && /* and we consumed our input */
        !Curl_bufq_is_full(&ctx->tunnel.recvbuf)) {

    nread = Curl_bufq_slurp(&ctx->inbufq, nw_in_reader, cf, &result);
    DEBUGF(LOG_CF(data, cf, "read %zd bytes nw data -> %zd, %d",
                  Curl_bufq_len(&ctx->inbufq), nread, result));
    if(nread < 0) {
      if(result != CURLE_AGAIN) {
        failf(data, "Failed receiving HTTP2 data");
        return result;
      }
      break;
    }
    else if(nread == 0) {
      ctx->conn_closed = TRUE;
      break;
    }

    if(h2_process_pending_input(cf, data, &result))
      return result;
  }

  if(ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) {
    connclose(cf->conn, "GOAWAY received");
  }

  return CURLE_OK;
}

/*
 * Check if there's been an update in the priority /
 * dependency settings and if so it submits a PRIORITY frame with the updated
 * info.
 * Flush any out data pending in the network buffer.
 */
static CURLcode h2_progress_egress(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  int rv = 0;

  rv = nghttp2_session_send(ctx->h2);
  if(nghttp2_is_fatal(rv)) {
    DEBUGF(LOG_CF(data, cf, "nghttp2_session_send error (%s)%d",
                  nghttp2_strerror(rv), rv));
    return CURLE_SEND_ERROR;
  }
  return nw_out_flush(cf, data);
}

static ssize_t on_session_send(nghttp2_session *h2,
                               const uint8_t *buf, size_t blen, int flags,
                               void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;
  CURLcode result = CURLE_OK;

  (void)h2;
  (void)flags;
  DEBUGASSERT(data);

  nwritten = Curl_bufq_write_pass(&ctx->outbufq, buf, blen,
                                  nw_out_writer, cf, &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      return NGHTTP2_ERR_WOULDBLOCK;
    }
    failf(data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(!nwritten)
    return NGHTTP2_ERR_WOULDBLOCK;

  return nwritten;
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  int32_t stream_id = frame->hd.stream_id;

  (void)session;
  DEBUGASSERT(data);
  if(!stream_id) {
    /* stream ID zero is for connection-oriented stuff */
    DEBUGASSERT(data);
    switch(frame->hd.type) {
    case NGHTTP2_SETTINGS:
      /* we do not do anything with this for now */
      break;
    case NGHTTP2_GOAWAY:
      infof(data, "recveived GOAWAY, error=%d, last_stream=%u",
                  frame->goaway.error_code, frame->goaway.last_stream_id);
      ctx->goaway = TRUE;
      break;
    case NGHTTP2_WINDOW_UPDATE:
      DEBUGF(LOG_CF(data, cf, "recv frame WINDOW_UPDATE"));
      break;
    default:
      DEBUGF(LOG_CF(data, cf, "recv frame %x on 0", frame->hd.type));
    }
    return 0;
  }

  if(stream_id != ctx->tunnel.stream_id) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] rcvd FRAME not for tunnel",
                  stream_id));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    /* If body started on this stream, then receiving DATA is illegal. */
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv frame DATA", stream_id));
    break;
  case NGHTTP2_HEADERS:
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv frame HEADERS", stream_id));

    /* nghttp2 guarantees that :status is received, and we store it to
       stream->status_code. Fuzzing has proven this can still be reached
       without status code having been set. */
    if(!ctx->tunnel.resp)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    /* Only final status code signals the end of header */
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] got http status: %d",
           stream_id, ctx->tunnel.resp->status));
    if(!ctx->tunnel.has_final_response) {
      if(ctx->tunnel.resp->status / 100 != 1) {
        ctx->tunnel.has_final_response = TRUE;
      }
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv PUSH_PROMISE", stream_id));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  case NGHTTP2_RST_STREAM:
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv RST", stream_id));
    ctx->tunnel.reset = TRUE;
    break;
  case NGHTTP2_WINDOW_UPDATE:
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv WINDOW_UPDATE", stream_id));
    if((data->req.keepon & KEEP_SEND_HOLD) &&
       (data->req.keepon & KEEP_SEND)) {
      data->req.keepon &= ~KEEP_SEND_HOLD;
      Curl_expire(data, 0, EXPIRE_RUN_NOW);
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] unpausing after win update",
             stream_id));
    }
    break;
  default:
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv frame %x",
                  stream_id, frame->hd.type));
    break;
  }
  return 0;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  int32_t stream_id = frame->hd.stream_id;
  CURLcode result;

  (void)flags;
  (void)data;
  (void)session;
  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */
  if(stream_id != ctx->tunnel.stream_id) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] header for non-tunnel stream: "
                  "%.*s: %.*s", stream_id,
                  (int)namelen, name,
                  (int)valuelen, value));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(frame->hd.type == NGHTTP2_PUSH_PROMISE)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  if(ctx->tunnel.has_final_response) {
    /* we do not do anything with trailers for tunnel streams */
    return 0;
  }

  if(namelen == sizeof(HTTP_PSEUDO_STATUS) - 1 &&
     memcmp(HTTP_PSEUDO_STATUS, name, namelen) == 0) {
    int http_status;
    struct http_resp *resp;

    /* status: always comes first, we might get more than one response,
     * link the previous ones for keepers */
    result = Curl_http_decode_status(&http_status,
                                    (const char *)value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    result = Curl_http_resp_make(&resp, http_status, NULL);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    resp->prev = ctx->tunnel.resp;
    ctx->tunnel.resp = resp;
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] status: HTTP/2 %03d",
                  stream_id, ctx->tunnel.resp->status));
    return 0;
  }

  if(!ctx->tunnel.resp)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  result = Curl_dynhds_add(&ctx->tunnel.resp->headers,
                           (const char *)name, namelen,
                           (const char *)value, valuelen);
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] header: %.*s: %.*s",
                stream_id,
                (int)namelen, name,
                (int)valuelen, value));

  return 0; /* 0 is successful */
}

static ssize_t tunnel_send_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint8_t *buf, size_t length,
                                    uint32_t *data_flags,
                                    nghttp2_data_source *source,
                                    void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct tunnel_stream *ts;
  CURLcode result;
  ssize_t nread;

  (void)source;
  (void)data;
  (void)ctx;

  if(!stream_id)
    return NGHTTP2_ERR_INVALID_ARGUMENT;

  ts = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!ts)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  DEBUGASSERT(ts == &ctx->tunnel);

  nread = Curl_bufq_read(&ts->sendbuf, buf, length, &result);
  if(nread < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    return NGHTTP2_ERR_DEFERRED;
  }
  if(ts->closed && Curl_bufq_is_empty(&ts->sendbuf))
    *data_flags = NGHTTP2_DATA_FLAG_EOF;

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] tunnel_send_callback -> %zd",
                ts->stream_id, nread));
  return nread;
}

static int tunnel_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id,
                                const uint8_t *mem, size_t len, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  ssize_t nwritten;
  CURLcode result;

  (void)flags;
  (void)session;
  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  if(stream_id != ctx->tunnel.stream_id)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  nwritten = Curl_bufq_write(&ctx->tunnel.recvbuf, mem, len, &result);
  if(nwritten < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    nwritten = 0;
  }
  DEBUGASSERT((size_t)nwritten == len);
  return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)session;
  (void)data;

  if(stream_id != ctx->tunnel.stream_id)
    return 0;

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] on_stream_close, %s (err %d)",
                stream_id, nghttp2_http2_strerror(error_code), error_code));
  ctx->tunnel.closed = TRUE;
  ctx->tunnel.error = error_code;

  return 0;
}

static CURLcode h2_submit(int32_t *pstream_id,
                          struct Curl_cfilter *cf,
                          struct Curl_easy *data,
                          nghttp2_session *h2,
                          struct httpreq *req,
                          const nghttp2_priority_spec *pri_spec,
                          void *stream_user_data,
                          nghttp2_data_source_read_callback read_callback,
                          void *read_ctx)
{
  struct dynhds h2_headers;
  nghttp2_nv *nva = NULL;
  unsigned int i;
  int32_t stream_id = -1;
  size_t nheader;
  CURLcode result;

  (void)cf;
  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);
  result = Curl_http_req_to_h2(&h2_headers, req, data);
  if(result)
    goto out;

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(nghttp2_nv) * nheader);
  if(!nva) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < nheader; ++i) {
    struct dynhds_entry *e = Curl_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].namelen = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].valuelen = e->valuelen;
    nva[i].flags = NGHTTP2_NV_FLAG_NONE;
  }

  if(read_callback) {
    nghttp2_data_provider data_prd;

    data_prd.read_callback = read_callback;
    data_prd.source.ptr = read_ctx;
    stream_id = nghttp2_submit_request(h2, pri_spec, nva, nheader,
                                       &data_prd, stream_user_data);
  }
  else {
    stream_id = nghttp2_submit_request(h2, pri_spec, nva, nheader,
                                       NULL, stream_user_data);
  }

  if(stream_id < 0) {
    failf(data, "nghttp2_session_upgrade2() failed: %s(%d)",
          nghttp2_strerror(stream_id), stream_id);
    result = CURLE_SEND_ERROR;
    goto out;
  }
  result = CURLE_OK;

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  *pstream_id = stream_id;
  return result;
}

static CURLcode submit_CONNECT(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct tunnel_stream *ts)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result;
  struct httpreq *req = NULL;

  infof(data, "Establish HTTP/2 proxy tunnel to %s", ts->authority);

  result = Curl_http_req_make(&req, "CONNECT", sizeof("CONNECT")-1,
                              NULL, 0, ts->authority, strlen(ts->authority),
                              NULL, 0);
  if(result)
    goto out;

  /* Setup the proxy-authorization header, if any */
  result = Curl_http_output_auth(data, cf->conn, req->method, HTTPREQ_GET,
                                 req->authority, TRUE);
  if(result)
    goto out;

  if(data->state.aptr.proxyuserpwd) {
    result = Curl_dynhds_h1_cadd_line(&req->headers,
                                      data->state.aptr.proxyuserpwd);
    if(result)
      goto out;
  }

  if(!Curl_checkProxyheaders(data, cf->conn, STRCONST("User-Agent"))
     && data->set.str[STRING_USERAGENT]) {
    result = Curl_dynhds_cadd(&req->headers, "User-Agent",
                              data->set.str[STRING_USERAGENT]);
    if(result)
      goto out;
  }

  result = Curl_dynhds_add_custom(data, TRUE, &req->headers);
  if(result)
    goto out;

  result = h2_submit(&ts->stream_id, cf, data, ctx->h2, req,
                     NULL, ts, tunnel_send_callback, cf);
  if(result) {
    DEBUGF(LOG_CF(data, cf, "send: nghttp2_submit_request error (%s)%u",
                  nghttp2_strerror(ts->stream_id), ts->stream_id));
  }

out:
  if(req)
    Curl_http_req_free(req);
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  return result;
}

static CURLcode inspect_response(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct tunnel_stream *ts)
{
  CURLcode result = CURLE_OK;
  struct dynhds_entry *auth_reply = NULL;
  (void)cf;

  DEBUGASSERT(ts->resp);
  if(ts->resp->status/100 == 2) {
    infof(data, "CONNECT tunnel established, response %d", ts->resp->status);
    tunnel_go_state(cf, ts, TUNNEL_ESTABLISHED, data);
    return CURLE_OK;
  }

  if(ts->resp->status == 401) {
    auth_reply = Curl_dynhds_cget(&ts->resp->headers, "WWW-Authenticate");
  }
  else if(ts->resp->status == 407) {
    auth_reply = Curl_dynhds_cget(&ts->resp->headers, "Proxy-Authenticate");
  }

  if(auth_reply) {
    DEBUGF(LOG_CF(data, cf, "CONNECT: fwd auth header '%s'",
                  auth_reply->value));
    result = Curl_http_input_auth(data, ts->resp->status == 407,
                                  auth_reply->value);
    if(result)
      return result;
    if(data->req.newurl) {
      /* Inidicator that we should try again */
      Curl_safefree(data->req.newurl);
      tunnel_go_state(cf, ts, TUNNEL_INIT, data);
      return CURLE_OK;
    }
  }

  /* Seems to have failed */
  return CURLE_RECV_ERROR;
}

static CURLcode CONNECT(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        struct tunnel_stream *ts)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(ts);
  DEBUGASSERT(ts->authority);
  do {
    switch(ts->state) {
    case TUNNEL_INIT:
      /* Prepare the CONNECT request and make a first attempt to send. */
      DEBUGF(LOG_CF(data, cf, "CONNECT start for %s", ts->authority));
      result = submit_CONNECT(cf, data, ts);
      if(result)
        goto out;
      tunnel_go_state(cf, ts, TUNNEL_CONNECT, data);
      /* FALLTHROUGH */

    case TUNNEL_CONNECT:
      /* see that the request is completely sent */
      result = h2_progress_ingress(cf, data);
      if(!result)
        result = h2_progress_egress(cf, data);
      if(result) {
        tunnel_go_state(cf, ts, TUNNEL_FAILED, data);
        break;
      }

      if(ts->has_final_response) {
        tunnel_go_state(cf, ts, TUNNEL_RESPONSE, data);
      }
      else {
        result = CURLE_OK;
        goto out;
      }
      /* FALLTHROUGH */

    case TUNNEL_RESPONSE:
      DEBUGASSERT(ts->has_final_response);
      result = inspect_response(cf, data, ts);
      if(result)
        goto out;
      break;

    case TUNNEL_ESTABLISHED:
      return CURLE_OK;

    case TUNNEL_FAILED:
      return CURLE_RECV_ERROR;

    default:
      break;
    }

  } while(ts->state == TUNNEL_INIT);

out:
  if(result || ctx->tunnel.closed)
    tunnel_go_state(cf, ts, TUNNEL_FAILED, data);
  return result;
}

static CURLcode cf_h2_proxy_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool blocking, bool *done)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  timediff_t check;
  struct tunnel_stream *ts = &ctx->tunnel;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the lower filters first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, blocking, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;

  CF_DATA_SAVE(save, cf, data);
  if(!ctx->h2) {
    result = cf_h2_proxy_ctx_init(cf, data);
    if(result)
      goto out;
  }
  DEBUGASSERT(ts->authority);

  check = Curl_timeleft(data, NULL, TRUE);
  if(check <= 0) {
    failf(data, "Proxy CONNECT aborted due to timeout");
    result = CURLE_OPERATION_TIMEDOUT;
    goto out;
  }

  /* for the secondary socket (FTP), use the "connect to host"
   * but ignore the "connect to port" (use the secondary port)
   */
  result = CONNECT(cf, data, ts);

out:
  *done = (result == CURLE_OK) && (ts->state == TUNNEL_ESTABLISHED);
  cf->connected = *done;
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_h2_proxy_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;

  if(ctx) {
    struct cf_call_data save;

    CF_DATA_SAVE(save, cf, data);
    cf_h2_proxy_ctx_clear(ctx);
    CF_DATA_RESTORE(cf, save);
  }
}

static void cf_h2_proxy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    cf_h2_proxy_ctx_free(ctx);
    cf->ctx = NULL;
  }
}

static bool cf_h2_proxy_data_pending(struct Curl_cfilter *cf,
                                     const struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  if((ctx && !Curl_bufq_is_empty(&ctx->inbufq)) ||
     (ctx && ctx->tunnel.state == TUNNEL_ESTABLISHED &&
      !Curl_bufq_is_empty(&ctx->tunnel.recvbuf)))
    return TRUE;
  return cf->next? cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

static int cf_h2_proxy_get_select_socks(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        curl_socket_t *sock)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  int bitmap = GETSOCK_BLANK;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  sock[0] = Curl_conn_cf_get_socket(cf, data);
  bitmap |= GETSOCK_READSOCK(0);

  /* HTTP/2 layer wants to send data) AND there's a window to send data in */
  if(nghttp2_session_want_write(ctx->h2) &&
     nghttp2_session_get_remote_window_size(ctx->h2))
    bitmap |= GETSOCK_WRITESOCK(0);

  CF_DATA_RESTORE(cf, save);
  return bitmap;
}

static ssize_t h2_handle_tunnel_close(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  ssize_t rv = 0;

  if(ctx->tunnel.error == NGHTTP2_REFUSED_STREAM) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] REFUSED_STREAM, try again on a new "
                  "connection", ctx->tunnel.stream_id));
    connclose(cf->conn, "REFUSED_STREAM"); /* don't use this anymore */
    *err = CURLE_RECV_ERROR; /* trigger Curl_retry_request() later */
    return -1;
  }
  else if(ctx->tunnel.error != NGHTTP2_NO_ERROR) {
    failf(data, "HTTP/2 stream %u was not closed cleanly: %s (err %u)",
          ctx->tunnel.stream_id, nghttp2_http2_strerror(ctx->tunnel.error),
          ctx->tunnel.error);
    *err = CURLE_HTTP2_STREAM;
    return -1;
  }
  else if(ctx->tunnel.reset) {
    failf(data, "HTTP/2 stream %u was reset", ctx->tunnel.stream_id);
    *err = CURLE_RECV_ERROR;
    return -1;
  }

  *err = CURLE_OK;
  rv = 0;
  DEBUGF(LOG_CF(data, cf, "handle_tunnel_close -> %zd, %d", rv, *err));
  return rv;
}

static ssize_t tunnel_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  ssize_t nread = -1;

  *err = CURLE_AGAIN;
  if(!Curl_bufq_is_empty(&ctx->tunnel.recvbuf)) {
    nread = Curl_bufq_read(&ctx->tunnel.recvbuf,
                           (unsigned char *)buf, len, err);
    if(nread < 0)
      goto out;
    DEBUGASSERT(nread > 0);
  }

  if(nread < 0) {
    if(ctx->tunnel.closed) {
      nread = h2_handle_tunnel_close(cf, data, err);
    }
    else if(ctx->tunnel.reset ||
            (ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) ||
            (ctx->goaway && ctx->last_stream_id < ctx->tunnel.stream_id)) {
      *err = CURLE_RECV_ERROR;
      nread = -1;
    }
  }
  else if(nread == 0) {
    *err = CURLE_AGAIN;
    nread = -1;
  }

out:
  DEBUGF(LOG_CF(data, cf, "tunnel_recv(len=%zu) -> %zd, %d",
                len, nread, *err));
  return nread;
}

static ssize_t cf_h2_proxy_recv(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  ssize_t nread = -1;
  struct cf_call_data save;
  CURLcode result;

  if(ctx->tunnel.state != TUNNEL_ESTABLISHED) {
    *err = CURLE_RECV_ERROR;
    return -1;
  }
  CF_DATA_SAVE(save, cf, data);

  if(Curl_bufq_is_empty(&ctx->tunnel.recvbuf)) {
    *err = h2_progress_ingress(cf, data);
    if(*err)
      goto out;
  }

  nread = tunnel_recv(cf, data, buf, len, err);

  if(nread > 0) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] increase window by %zd",
                  ctx->tunnel.stream_id, nread));
    nghttp2_session_consume(ctx->h2, ctx->tunnel.stream_id, (size_t)nread);
  }

  result = h2_progress_egress(cf, data);
  if(result) {
    *err = result;
    nread = -1;
  }

out:
  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_recv(len=%zu) -> %zd %d",
                ctx->tunnel.stream_id, len, nread, *err));
  CF_DATA_RESTORE(cf, save);
  return nread;
}

static ssize_t cf_h2_proxy_send(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const void *mem, size_t len, CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  ssize_t nwritten = -1;
  const unsigned char *buf = mem;
  size_t start_len = len;
  int rv;

  if(ctx->tunnel.state != TUNNEL_ESTABLISHED) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }
  CF_DATA_SAVE(save, cf, data);

  while(len) {
    nwritten = Curl_bufq_write(&ctx->tunnel.sendbuf, buf, len, err);
    if(nwritten <= 0) {
      if(*err && *err != CURLE_AGAIN) {
        DEBUGF(LOG_CF(data, cf, "error adding data to tunnel sendbuf: %d",
               *err));
        nwritten = -1;
        goto out;
      }
      /* blocked */
      nwritten = 0;
    }
    else {
      DEBUGASSERT((size_t)nwritten <= len);
      buf += (size_t)nwritten;
      len -= (size_t)nwritten;
    }

    /* resume the tunnel stream and let the h2 session send, which
     * triggers reading from tunnel.sendbuf */
    rv = nghttp2_session_resume_data(ctx->h2, ctx->tunnel.stream_id);
    if(nghttp2_is_fatal(rv)) {
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
      goto out;
    }
    *err = h2_progress_egress(cf, data);
    if(*err) {
      nwritten = -1;
      goto out;
    }

    if(!nwritten && Curl_bufq_is_full(&ctx->tunnel.sendbuf)) {
      size_t rwin;
      /* we could not add to the buffer and after session processing,
       * it is still full. */
      rwin = nghttp2_session_get_stream_remote_window_size(
                                        ctx->h2, ctx->tunnel.stream_id);
      DEBUGF(LOG_CF(data, cf, "cf_send: tunnel win %u/%zu",
             nghttp2_session_get_remote_window_size(ctx->h2), rwin));
      if(rwin == 0) {
        /* We cannot upload more as the stream's remote window size
         * is 0. We need to receive WIN_UPDATEs before we can continue.
         */
        data->req.keepon |= KEEP_SEND_HOLD;
        DEBUGF(LOG_CF(data, cf, "pausing send as remote flow "
               "window is exhausted"));
      }
      break;
    }
  }

  nwritten = start_len - len;
  if(nwritten > 0) {
    *err = CURLE_OK;
  }
  else if(ctx->tunnel.closed) {
    nwritten = -1;
    *err = CURLE_SEND_ERROR;
  }
  else {
    nwritten = -1;
    *err = CURLE_AGAIN;
  }

out:
  DEBUGF(LOG_CF(data, cf, "cf_send(len=%zu) -> %zd, %d ",
         start_len, nwritten, *err));
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

struct Curl_cftype Curl_cft_h2_proxy = {
  "H2-PROXY",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_DEFAULT,
  cf_h2_proxy_destroy,
  cf_h2_proxy_connect,
  cf_h2_proxy_close,
  Curl_cf_http_proxy_get_host,
  cf_h2_proxy_get_select_socks,
  cf_h2_proxy_data_pending,
  cf_h2_proxy_send,
  cf_h2_proxy_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

CURLcode Curl_cf_h2_proxy_insert_after(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  struct Curl_cfilter *cf_h2_proxy = NULL;
  struct cf_h2_proxy_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  (void)data;
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx)
    goto out;

  result = Curl_cf_create(&cf_h2_proxy, &Curl_cft_h2_proxy, ctx);
  if(result)
    goto out;

  Curl_conn_cf_insert_after(cf, cf_h2_proxy);
  result = CURLE_OK;

out:
  if(result)
    cf_h2_proxy_ctx_free(ctx);
  return result;
}

#endif /* defined(USE_NGHTTP2) && !defined(CURL_DISABLE_PROXY) */
