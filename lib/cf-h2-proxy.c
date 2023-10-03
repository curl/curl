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
#include "curl_trc.h"
#include "bufq.h"
#include "dynbuf.h"
#include "dynhds.h"
#include "http1.h"
#include "http2.h"
#include "http_proxy.h"
#include "multiif.h"
#include "cf-h2-proxy.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define PROXY_H2_CHUNK_SIZE  (16*1024)

#define PROXY_HTTP2_HUGE_WINDOW_SIZE (100 * 1024 * 1024)
#define H2_TUNNEL_WINDOW_SIZE        (10 * 1024 * 1024)

#define PROXY_H2_NW_RECV_CHUNKS  (H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE)
#define PROXY_H2_NW_SEND_CHUNKS   1

#define H2_TUNNEL_RECV_CHUNKS   (H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE)
#define H2_TUNNEL_SEND_CHUNKS   ((128 * 1024) / PROXY_H2_CHUNK_SIZE)


typedef enum {
    H2_TUNNEL_INIT,     /* init/default/no tunnel state */
    H2_TUNNEL_CONNECT,  /* CONNECT request is being send */
    H2_TUNNEL_RESPONSE, /* CONNECT response received completely */
    H2_TUNNEL_ESTABLISHED,
    H2_TUNNEL_FAILED
} h2_tunnel_state;

struct tunnel_stream {
  struct http_resp *resp;
  struct bufq recvbuf;
  struct bufq sendbuf;
  char *authority;
  int32_t stream_id;
  uint32_t error;
  size_t upload_blocked_len;
  h2_tunnel_state state;
  BIT(has_final_response);
  BIT(closed);
  BIT(reset);
};

static CURLcode tunnel_stream_init(struct Curl_cfilter *cf,
                                    struct tunnel_stream *ts)
{
  const char *hostname;
  int port;
  bool ipv6_ip;
  CURLcode result;

  ts->state = H2_TUNNEL_INIT;
  ts->stream_id = -1;
  Curl_bufq_init2(&ts->recvbuf, PROXY_H2_CHUNK_SIZE, H2_TUNNEL_RECV_CHUNKS,
                  BUFQ_OPT_SOFT_LIMIT);
  Curl_bufq_init(&ts->sendbuf, PROXY_H2_CHUNK_SIZE, H2_TUNNEL_SEND_CHUNKS);

  result = Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip);
  if(result)
    return result;

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
  ts->state = H2_TUNNEL_INIT;
}

static void h2_tunnel_go_state(struct Curl_cfilter *cf,
                               struct tunnel_stream *ts,
                               h2_tunnel_state new_state,
                               struct Curl_easy *data)
{
  (void)cf;

  if(ts->state == new_state)
    return;
  /* leaving this one */
  switch(ts->state) {
  case H2_TUNNEL_CONNECT:
    data->req.ignorebody = FALSE;
    break;
  default:
    break;
  }
  /* entering this one */
  switch(new_state) {
  case H2_TUNNEL_INIT:
    CURL_TRC_CF(data, cf, "[%d] new tunnel state 'init'", ts->stream_id);
    tunnel_stream_clear(ts);
    break;

  case H2_TUNNEL_CONNECT:
    CURL_TRC_CF(data, cf, "[%d] new tunnel state 'connect'", ts->stream_id);
    ts->state = H2_TUNNEL_CONNECT;
    break;

  case H2_TUNNEL_RESPONSE:
    CURL_TRC_CF(data, cf, "[%d] new tunnel state 'response'", ts->stream_id);
    ts->state = H2_TUNNEL_RESPONSE;
    break;

  case H2_TUNNEL_ESTABLISHED:
    CURL_TRC_CF(data, cf, "[%d] new tunnel state 'established'",
                ts->stream_id);
    infof(data, "CONNECT phase completed");
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    /* FALLTHROUGH */
  case H2_TUNNEL_FAILED:
    if(new_state == H2_TUNNEL_FAILED)
      CURL_TRC_CF(data, cf, "[%d] new tunnel state 'failed'", ts->stream_id);
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
  BIT(nw_out_blocked);
};

/* How to access `call_data` from a cf_h2 filter */
#undef CF_CTX_CALL_DATA
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

static void drain_tunnel(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         struct tunnel_stream *tunnel)
{
  unsigned char bits;

  (void)cf;
  bits = CURL_CSELECT_IN;
  if(!tunnel->closed && !tunnel->reset && tunnel->upload_blocked_len)
    bits |= CURL_CSELECT_OUT;
  if(data->state.dselect_bits != bits) {
    CURL_TRC_CF(data, cf, "[%d] DRAIN dselect_bits=%x",
                tunnel->stream_id, bits);
    data->state.dselect_bits = bits;
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
}

static ssize_t proxy_nw_in_reader(void *reader_ctx,
                                  unsigned char *buf, size_t buflen,
                                  CURLcode *err)
{
  struct Curl_cfilter *cf = reader_ctx;
  ssize_t nread;

  if(cf) {
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    nread = Curl_conn_cf_recv(cf->next, data, (char *)buf, buflen, err);
    CURL_TRC_CF(data, cf, "[0] nw_in_reader(len=%zu) -> %zd, %d",
                buflen, nread, *err);
  }
  else {
    nread = 0;
  }
  return nread;
}

static ssize_t proxy_h2_nw_out_writer(void *writer_ctx,
                                      const unsigned char *buf, size_t buflen,
                                      CURLcode *err)
{
  struct Curl_cfilter *cf = writer_ctx;
  ssize_t nwritten;

  if(cf) {
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    nwritten = Curl_conn_cf_send(cf->next, data, (const char *)buf, buflen,
                                 err);
    CURL_TRC_CF(data, cf, "[0] nw_out_writer(len=%zu) -> %zd, %d",
                buflen, nwritten, *err);
  }
  else {
    nwritten = 0;
  }
  return nwritten;
}

static int proxy_h2_client_new(struct Curl_cfilter *cf,
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
static int proxy_h2_on_frame_recv(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *userp);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
static int proxy_h2_on_frame_send(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *userp);
#endif
static int proxy_h2_on_stream_close(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code, void *userp);
static int proxy_h2_on_header(nghttp2_session *session,
                              const nghttp2_frame *frame,
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

  Curl_bufq_init(&ctx->inbufq, PROXY_H2_CHUNK_SIZE, PROXY_H2_NW_RECV_CHUNKS);
  Curl_bufq_init(&ctx->outbufq, PROXY_H2_CHUNK_SIZE, PROXY_H2_NW_SEND_CHUNKS);

  if(tunnel_stream_init(cf, &ctx->tunnel))
    goto out;

  rc = nghttp2_session_callbacks_new(&cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2 callbacks");
    goto out;
  }

  nghttp2_session_callbacks_set_send_callback(cbs, on_session_send);
  nghttp2_session_callbacks_set_on_frame_recv_callback(
    cbs, proxy_h2_on_frame_recv);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  nghttp2_session_callbacks_set_on_frame_send_callback(cbs,
                                                       proxy_h2_on_frame_send);
#endif
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    cbs, tunnel_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
    cbs, proxy_h2_on_stream_close);
  nghttp2_session_callbacks_set_on_header_callback(cbs, proxy_h2_on_header);

  /* The nghttp2 session is not yet setup, do it */
  rc = proxy_h2_client_new(cf, cbs);
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
                                             PROXY_HTTP2_HUGE_WINDOW_SIZE);
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
  CURL_TRC_CF(data, cf, "[0] init proxy ctx -> %d", result);
  return result;
}

static int proxy_h2_should_close_session(struct cf_h2_proxy_ctx *ctx)
{
  return !nghttp2_session_want_read(ctx->h2) &&
    !nghttp2_session_want_write(ctx->h2);
}

static CURLcode proxy_h2_nw_out_flush(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  ssize_t nwritten;
  CURLcode result;

  (void)data;
  if(Curl_bufq_is_empty(&ctx->outbufq))
    return CURLE_OK;

  nwritten = Curl_bufq_pass(&ctx->outbufq, proxy_h2_nw_out_writer, cf,
                            &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "[0] flush nw send buffer(%zu) -> EAGAIN",
                  Curl_bufq_len(&ctx->outbufq));
      ctx->nw_out_blocked = 1;
    }
    return result;
  }
  CURL_TRC_CF(data, cf, "[0] nw send buffer flushed");
  return Curl_bufq_is_empty(&ctx->outbufq)? CURLE_OK: CURLE_AGAIN;
}

/*
 * Processes pending input left in network input buffer.
 * This function returns 0 if it succeeds, or -1 and error code will
 * be assigned to *err.
 */
static int proxy_h2_process_pending_input(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  const unsigned char *buf;
  size_t blen;
  ssize_t rv;

  while(Curl_bufq_peek(&ctx->inbufq, &buf, &blen)) {

    rv = nghttp2_session_mem_recv(ctx->h2, (const uint8_t *)buf, blen);
    CURL_TRC_CF(data, cf, "[0] %zu bytes to nghttp2 -> %zd", blen, rv);
    if(rv < 0) {
      failf(data,
            "process_pending_input: nghttp2_session_mem_recv() returned "
            "%zd:%s", rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
      return -1;
    }
    Curl_bufq_skip(&ctx->inbufq, (size_t)rv);
    if(Curl_bufq_is_empty(&ctx->inbufq)) {
      CURL_TRC_CF(data, cf, "[0] all data in connection buffer processed");
      break;
    }
    else {
      CURL_TRC_CF(data, cf, "[0] process_pending_input: %zu bytes left "
                  "in connection buffer", Curl_bufq_len(&ctx->inbufq));
    }
  }

  return 0;
}

static CURLcode proxy_h2_progress_ingress(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  ssize_t nread;

  /* Process network input buffer fist */
  if(!Curl_bufq_is_empty(&ctx->inbufq)) {
    CURL_TRC_CF(data, cf, "[0] process %zu bytes in connection buffer",
                Curl_bufq_len(&ctx->inbufq));
    if(proxy_h2_process_pending_input(cf, data, &result) < 0)
      return result;
  }

  /* Receive data from the "lower" filters, e.g. network until
   * it is time to stop or we have enough data for this stream */
  while(!ctx->conn_closed &&               /* not closed the connection */
        !ctx->tunnel.closed &&             /* nor the tunnel */
        Curl_bufq_is_empty(&ctx->inbufq) && /* and we consumed our input */
        !Curl_bufq_is_full(&ctx->tunnel.recvbuf)) {

    nread = Curl_bufq_slurp(&ctx->inbufq, proxy_nw_in_reader, cf, &result);
    CURL_TRC_CF(data, cf, "[0] read %zu bytes nw data -> %zd, %d",
                Curl_bufq_len(&ctx->inbufq), nread, result);
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

    if(proxy_h2_process_pending_input(cf, data, &result))
      return result;
  }

  if(ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) {
    connclose(cf->conn, "GOAWAY received");
  }

  return CURLE_OK;
}

static CURLcode proxy_h2_progress_egress(struct Curl_cfilter *cf,
                                         struct Curl_easy *data)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  int rv = 0;

  ctx->nw_out_blocked = 0;
  while(!rv && !ctx->nw_out_blocked && nghttp2_session_want_write(ctx->h2))
    rv = nghttp2_session_send(ctx->h2);

  if(nghttp2_is_fatal(rv)) {
    CURL_TRC_CF(data, cf, "[0] nghttp2_session_send error (%s)%d",
                nghttp2_strerror(rv), rv);
    return CURLE_SEND_ERROR;
  }
  return proxy_h2_nw_out_flush(cf, data);
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
                                  proxy_h2_nw_out_writer, cf, &result);
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

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static int proxy_h2_fr_print(const nghttp2_frame *frame,
                             char *buffer, size_t blen)
{
  switch(frame->hd.type) {
    case NGHTTP2_DATA: {
      return msnprintf(buffer, blen,
                       "FRAME[DATA, len=%d, eos=%d, padlen=%d]",
                       (int)frame->hd.length,
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM),
                       (int)frame->data.padlen);
    }
    case NGHTTP2_HEADERS: {
      return msnprintf(buffer, blen,
                       "FRAME[HEADERS, len=%d, hend=%d, eos=%d]",
                       (int)frame->hd.length,
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS),
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM));
    }
    case NGHTTP2_PRIORITY: {
      return msnprintf(buffer, blen,
                       "FRAME[PRIORITY, len=%d, flags=%d]",
                       (int)frame->hd.length, frame->hd.flags);
    }
    case NGHTTP2_RST_STREAM: {
      return msnprintf(buffer, blen,
                       "FRAME[RST_STREAM, len=%d, flags=%d, error=%u]",
                       (int)frame->hd.length, frame->hd.flags,
                       frame->rst_stream.error_code);
    }
    case NGHTTP2_SETTINGS: {
      if(frame->hd.flags & NGHTTP2_FLAG_ACK) {
        return msnprintf(buffer, blen, "FRAME[SETTINGS, ack=1]");
      }
      return msnprintf(buffer, blen,
                       "FRAME[SETTINGS, len=%d]", (int)frame->hd.length);
    }
    case NGHTTP2_PUSH_PROMISE: {
      return msnprintf(buffer, blen,
                       "FRAME[PUSH_PROMISE, len=%d, hend=%d]",
                       (int)frame->hd.length,
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS));
    }
    case NGHTTP2_PING: {
      return msnprintf(buffer, blen,
                       "FRAME[PING, len=%d, ack=%d]",
                       (int)frame->hd.length,
                       frame->hd.flags&NGHTTP2_FLAG_ACK);
    }
    case NGHTTP2_GOAWAY: {
      char scratch[128];
      size_t s_len = sizeof(scratch)/sizeof(scratch[0]);
        size_t len = (frame->goaway.opaque_data_len < s_len)?
                      frame->goaway.opaque_data_len : s_len-1;
        if(len)
          memcpy(scratch, frame->goaway.opaque_data, len);
        scratch[len] = '\0';
        return msnprintf(buffer, blen, "FRAME[GOAWAY, error=%d, reason='%s', "
                         "last_stream=%d]", frame->goaway.error_code,
                         scratch, frame->goaway.last_stream_id);
    }
    case NGHTTP2_WINDOW_UPDATE: {
      return msnprintf(buffer, blen,
                       "FRAME[WINDOW_UPDATE, incr=%d]",
                       frame->window_update.window_size_increment);
    }
    default:
      return msnprintf(buffer, blen, "FRAME[%d, len=%d, flags=%d]",
                       frame->hd.type, (int)frame->hd.length,
                       frame->hd.flags);
  }
}

static int proxy_h2_on_frame_send(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)session;
  DEBUGASSERT(data);
  if(data && Curl_trc_cf_is_verbose(cf, data)) {
    char buffer[256];
    int len;
    len = proxy_h2_fr_print(frame, buffer, sizeof(buffer)-1);
    buffer[len] = 0;
    CURL_TRC_CF(data, cf, "[%d] -> %s", frame->hd.stream_id, buffer);
  }
  return 0;
}
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

static int proxy_h2_on_frame_recv(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  int32_t stream_id = frame->hd.stream_id;

  (void)session;
  DEBUGASSERT(data);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(Curl_trc_cf_is_verbose(cf, data)) {
    char buffer[256];
    int len;
    len = proxy_h2_fr_print(frame, buffer, sizeof(buffer)-1);
    buffer[len] = 0;
    CURL_TRC_CF(data, cf, "[%d] <- %s",frame->hd.stream_id, buffer);
  }
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

  if(!stream_id) {
    /* stream ID zero is for connection-oriented stuff */
    DEBUGASSERT(data);
    switch(frame->hd.type) {
    case NGHTTP2_SETTINGS:
      /* Since the initial stream window is 64K, a request might be on HOLD,
       * due to exhaustion. The (initial) SETTINGS may announce a much larger
       * window and *assume* that we treat this like a WINDOW_UPDATE. Some
       * servers send an explicit WINDOW_UPDATE, but not all seem to do that.
       * To be safe, we UNHOLD a stream in order not to stall. */
      if((data->req.keepon & KEEP_SEND_HOLD) &&
         (data->req.keepon & KEEP_SEND)) {
        data->req.keepon &= ~KEEP_SEND_HOLD;
        drain_tunnel(cf, data, &ctx->tunnel);
        CURL_TRC_CF(data, cf, "[%d] un-holding after SETTINGS",
                    stream_id);
      }
      break;
    case NGHTTP2_GOAWAY:
      ctx->goaway = TRUE;
      break;
    default:
      break;
    }
    return 0;
  }

  if(stream_id != ctx->tunnel.stream_id) {
    CURL_TRC_CF(data, cf, "[%d] rcvd FRAME not for tunnel", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    /* nghttp2 guarantees that :status is received, and we store it to
       stream->status_code. Fuzzing has proven this can still be reached
       without status code having been set. */
    if(!ctx->tunnel.resp)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    /* Only final status code signals the end of header */
    CURL_TRC_CF(data, cf, "[%d] got http status: %d",
                stream_id, ctx->tunnel.resp->status);
    if(!ctx->tunnel.has_final_response) {
      if(ctx->tunnel.resp->status / 100 != 1) {
        ctx->tunnel.has_final_response = TRUE;
      }
    }
    break;
  case NGHTTP2_WINDOW_UPDATE:
    if((data->req.keepon & KEEP_SEND_HOLD) &&
       (data->req.keepon & KEEP_SEND)) {
      data->req.keepon &= ~KEEP_SEND_HOLD;
      Curl_expire(data, 0, EXPIRE_RUN_NOW);
      CURL_TRC_CF(data, cf, "[%d] unpausing after win update",
                  stream_id);
    }
    break;
  default:
    break;
  }
  return 0;
}

static int proxy_h2_on_header(nghttp2_session *session,
                              const nghttp2_frame *frame,
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
    CURL_TRC_CF(data, cf, "[%d] header for non-tunnel stream: "
                "%.*s: %.*s", stream_id,
                (int)namelen, name, (int)valuelen, value);
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
    CURL_TRC_CF(data, cf, "[%d] status: HTTP/2 %03d",
                stream_id, ctx->tunnel.resp->status);
    return 0;
  }

  if(!ctx->tunnel.resp)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  result = Curl_dynhds_add(&ctx->tunnel.resp->headers,
                           (const char *)name, namelen,
                           (const char *)value, valuelen);
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  CURL_TRC_CF(data, cf, "[%d] header: %.*s: %.*s",
              stream_id, (int)namelen, name, (int)valuelen, value);

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

  CURL_TRC_CF(data, cf, "[%d] tunnel_send_callback -> %zd",
              ts->stream_id, nread);
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

static int proxy_h2_on_stream_close(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)session;
  (void)data;

  if(stream_id != ctx->tunnel.stream_id)
    return 0;

  CURL_TRC_CF(data, cf, "[%d] proxy_h2_on_stream_close, %s (err %d)",
              stream_id, nghttp2_http2_strerror(error_code), error_code);
  ctx->tunnel.closed = TRUE;
  ctx->tunnel.error = error_code;

  return 0;
}

static CURLcode proxy_h2_submit(int32_t *pstream_id,
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

  result = Curl_http_proxy_create_CONNECT(&req, cf, data, 2);
  if(result)
    goto out;

  infof(data, "Establish HTTP/2 proxy tunnel to %s", req->authority);

  result = proxy_h2_submit(&ts->stream_id, cf, data, ctx->h2, req,
                           NULL, ts, tunnel_send_callback, cf);
  if(result) {
    CURL_TRC_CF(data, cf, "[%d] send, nghttp2_submit_request error: %s",
                ts->stream_id, nghttp2_strerror(ts->stream_id));
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
    h2_tunnel_go_state(cf, ts, H2_TUNNEL_ESTABLISHED, data);
    return CURLE_OK;
  }

  if(ts->resp->status == 401) {
    auth_reply = Curl_dynhds_cget(&ts->resp->headers, "WWW-Authenticate");
  }
  else if(ts->resp->status == 407) {
    auth_reply = Curl_dynhds_cget(&ts->resp->headers, "Proxy-Authenticate");
  }

  if(auth_reply) {
    CURL_TRC_CF(data, cf, "[0] CONNECT: fwd auth header '%s'",
                auth_reply->value);
    result = Curl_http_input_auth(data, ts->resp->status == 407,
                                  auth_reply->value);
    if(result)
      return result;
    if(data->req.newurl) {
      /* Indicator that we should try again */
      Curl_safefree(data->req.newurl);
      h2_tunnel_go_state(cf, ts, H2_TUNNEL_INIT, data);
      return CURLE_OK;
    }
  }

  /* Seems to have failed */
  return CURLE_RECV_ERROR;
}

static CURLcode H2_CONNECT(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct tunnel_stream *ts)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(ts);
  DEBUGASSERT(ts->authority);
  do {
    switch(ts->state) {
    case H2_TUNNEL_INIT:
      /* Prepare the CONNECT request and make a first attempt to send. */
      CURL_TRC_CF(data, cf, "[0] CONNECT start for %s", ts->authority);
      result = submit_CONNECT(cf, data, ts);
      if(result)
        goto out;
      h2_tunnel_go_state(cf, ts, H2_TUNNEL_CONNECT, data);
      /* FALLTHROUGH */

    case H2_TUNNEL_CONNECT:
      /* see that the request is completely sent */
      result = proxy_h2_progress_ingress(cf, data);
      if(!result)
        result = proxy_h2_progress_egress(cf, data);
      if(result && result != CURLE_AGAIN) {
        h2_tunnel_go_state(cf, ts, H2_TUNNEL_FAILED, data);
        break;
      }

      if(ts->has_final_response) {
        h2_tunnel_go_state(cf, ts, H2_TUNNEL_RESPONSE, data);
      }
      else {
        result = CURLE_OK;
        goto out;
      }
      /* FALLTHROUGH */

    case H2_TUNNEL_RESPONSE:
      DEBUGASSERT(ts->has_final_response);
      result = inspect_response(cf, data, ts);
      if(result)
        goto out;
      break;

    case H2_TUNNEL_ESTABLISHED:
      return CURLE_OK;

    case H2_TUNNEL_FAILED:
      return CURLE_RECV_ERROR;

    default:
      break;
    }

  } while(ts->state == H2_TUNNEL_INIT);

out:
  if(result || ctx->tunnel.closed)
    h2_tunnel_go_state(cf, ts, H2_TUNNEL_FAILED, data);
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
  result = H2_CONNECT(cf, data, ts);

out:
  *done = (result == CURLE_OK) && (ts->state == H2_TUNNEL_ESTABLISHED);
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
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
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
     (ctx && ctx->tunnel.state == H2_TUNNEL_ESTABLISHED &&
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
    CURL_TRC_CF(data, cf, "[%d] REFUSED_STREAM, try again on a new "
                "connection", ctx->tunnel.stream_id);
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
  CURL_TRC_CF(data, cf, "[%d] handle_tunnel_close -> %zd, %d",
              ctx->tunnel.stream_id, rv, *err);
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
  CURL_TRC_CF(data, cf, "[%d] tunnel_recv(len=%zu) -> %zd, %d",
              ctx->tunnel.stream_id, len, nread, *err);
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

  if(ctx->tunnel.state != H2_TUNNEL_ESTABLISHED) {
    *err = CURLE_RECV_ERROR;
    return -1;
  }
  CF_DATA_SAVE(save, cf, data);

  if(Curl_bufq_is_empty(&ctx->tunnel.recvbuf)) {
    *err = proxy_h2_progress_ingress(cf, data);
    if(*err)
      goto out;
  }

  nread = tunnel_recv(cf, data, buf, len, err);

  if(nread > 0) {
    CURL_TRC_CF(data, cf, "[%d] increase window by %zd",
                ctx->tunnel.stream_id, nread);
    nghttp2_session_consume(ctx->h2, ctx->tunnel.stream_id, (size_t)nread);
  }

  result = proxy_h2_progress_egress(cf, data);
  if(result == CURLE_AGAIN) {
    /* pending data to send, need to be called again. Ideally, we'd
     * monitor the socket for POLLOUT, but we might not be in SENDING
     * transfer state any longer and are unable to make this happen.
     */
    CURL_TRC_CF(data, cf, "[%d] egress blocked, DRAIN",
                ctx->tunnel.stream_id);
    drain_tunnel(cf, data, &ctx->tunnel);
  }
  else if(result) {
    *err = result;
    nread = -1;
  }

out:
  if(!Curl_bufq_is_empty(&ctx->tunnel.recvbuf) &&
     (nread >= 0 || *err == CURLE_AGAIN)) {
    /* data pending and no fatal error to report. Need to trigger
     * draining to avoid stalling when no socket events happen. */
    drain_tunnel(cf, data, &ctx->tunnel);
  }
  CURL_TRC_CF(data, cf, "[%d] cf_recv(len=%zu) -> %zd %d",
              ctx->tunnel.stream_id, len, nread, *err);
  CF_DATA_RESTORE(cf, save);
  return nread;
}

static ssize_t cf_h2_proxy_send(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const void *buf, size_t len, CURLcode *err)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  int rv;
  ssize_t nwritten;
  CURLcode result;
  int blocked = 0;

  if(ctx->tunnel.state != H2_TUNNEL_ESTABLISHED) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }
  CF_DATA_SAVE(save, cf, data);

  if(ctx->tunnel.closed) {
    nwritten = -1;
    *err = CURLE_SEND_ERROR;
    goto out;
  }
  else if(ctx->tunnel.upload_blocked_len) {
    /* the data in `buf` has already been submitted or added to the
     * buffers, but have been EAGAINed on the last invocation. */
    DEBUGASSERT(len >= ctx->tunnel.upload_blocked_len);
    if(len < ctx->tunnel.upload_blocked_len) {
      /* Did we get called again with a smaller `len`? This should not
       * happen. We are not prepared to handle that. */
      failf(data, "HTTP/2 proxy, send again with decreased length");
      *err = CURLE_HTTP2;
      nwritten = -1;
      goto out;
    }
    nwritten = (ssize_t)ctx->tunnel.upload_blocked_len;
    ctx->tunnel.upload_blocked_len = 0;
    *err = CURLE_OK;
  }
  else {
    nwritten = Curl_bufq_write(&ctx->tunnel.sendbuf, buf, len, err);
    if(nwritten < 0) {
      if(*err != CURLE_AGAIN)
        goto out;
      nwritten = 0;
    }
  }

  if(!Curl_bufq_is_empty(&ctx->tunnel.sendbuf)) {
    /* req body data is buffered, resume the potentially suspended stream */
    rv = nghttp2_session_resume_data(ctx->h2, ctx->tunnel.stream_id);
    if(nghttp2_is_fatal(rv)) {
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
      goto out;
    }
  }

  result = proxy_h2_progress_ingress(cf, data);
  if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }

  /* Call the nghttp2 send loop and flush to write ALL buffered data,
   * headers and/or request body completely out to the network */
  result = proxy_h2_progress_egress(cf, data);
  if(result == CURLE_AGAIN) {
    blocked = 1;
  }
  else if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }
  else if(!Curl_bufq_is_empty(&ctx->tunnel.sendbuf)) {
    /* although we wrote everything that nghttp2 wants to send now,
     * there is data left in our stream send buffer unwritten. This may
     * be due to the stream's HTTP/2 flow window being exhausted. */
    blocked = 1;
  }

  if(blocked) {
    /* Unable to send all data, due to connection blocked or H2 window
     * exhaustion. Data is left in our stream buffer, or nghttp2's internal
     * frame buffer or our network out buffer. */
    size_t rwin = nghttp2_session_get_stream_remote_window_size(
                    ctx->h2, ctx->tunnel.stream_id);
    if(rwin == 0) {
      /* H2 flow window exhaustion.
       * FIXME: there is no way to HOLD all transfers that use this
       * proxy connection AND to UNHOLD all of them again when the
       * window increases.
       * We *could* iterate over all data on this conn maybe? */
      CURL_TRC_CF(data, cf, "[%d] remote flow "
                  "window is exhausted", ctx->tunnel.stream_id);
    }

    /* Whatever the cause, we need to return CURL_EAGAIN for this call.
     * We have unwritten state that needs us being invoked again and EAGAIN
     * is the only way to ensure that. */
    ctx->tunnel.upload_blocked_len = nwritten;
    CURL_TRC_CF(data, cf, "[%d] cf_send(len=%zu) BLOCK: win %u/%zu "
                "blocked_len=%zu",
                ctx->tunnel.stream_id, len,
                nghttp2_session_get_remote_window_size(ctx->h2), rwin,
                nwritten);
    drain_tunnel(cf, data, &ctx->tunnel);
    *err = CURLE_AGAIN;
    nwritten = -1;
    goto out;
  }
  else if(proxy_h2_should_close_session(ctx)) {
    /* nghttp2 thinks this session is done. If the stream has not been
     * closed, this is an error state for out transfer */
    if(ctx->tunnel.closed) {
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
    }
    else {
      CURL_TRC_CF(data, cf, "[0] send: nothing to do in this session");
      *err = CURLE_HTTP2;
      nwritten = -1;
    }
  }

out:
  if(!Curl_bufq_is_empty(&ctx->tunnel.recvbuf) &&
     (nwritten >= 0 || *err == CURLE_AGAIN)) {
    /* data pending and no fatal error to report. Need to trigger
     * draining to avoid stalling when no socket events happen. */
    drain_tunnel(cf, data, &ctx->tunnel);
  }
  CURL_TRC_CF(data, cf, "[%d] cf_send(len=%zu) -> %zd, %d, "
              "h2 windows %d-%d (stream-conn), buffers %zu-%zu (stream-conn)",
              ctx->tunnel.stream_id, len, nwritten, *err,
              nghttp2_session_get_stream_remote_window_size(
                  ctx->h2, ctx->tunnel.stream_id),
              nghttp2_session_get_remote_window_size(ctx->h2),
              Curl_bufq_len(&ctx->tunnel.sendbuf),
              Curl_bufq_len(&ctx->outbufq));
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

static bool proxy_h2_connisalive(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *input_pending)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  bool alive = TRUE;

  *input_pending = FALSE;
  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    return FALSE;

  if(*input_pending) {
    /* This happens before we've sent off a request and the connection is
       not in use by any other transfer, there shouldn't be any data here,
       only "protocol frames" */
    CURLcode result;
    ssize_t nread = -1;

    *input_pending = FALSE;
    nread = Curl_bufq_slurp(&ctx->inbufq, proxy_nw_in_reader, cf, &result);
    if(nread != -1) {
      if(proxy_h2_process_pending_input(cf, data, &result) < 0)
        /* immediate error, considered dead */
        alive = FALSE;
      else {
        alive = !proxy_h2_should_close_session(ctx);
      }
    }
    else if(result != CURLE_AGAIN) {
      /* the read failed so let's say this is dead anyway */
      alive = FALSE;
    }
  }

  return alive;
}

static bool cf_h2_proxy_is_alive(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *input_pending)
{
  struct cf_h2_proxy_ctx *ctx = cf->ctx;
  CURLcode result;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  result = (ctx && ctx->h2 && proxy_h2_connisalive(cf, data, input_pending));
  CURL_TRC_CF(data, cf, "[0] conn alive -> %d, input_pending=%d",
              result, *input_pending);
  CF_DATA_RESTORE(cf, save);
  return result;
}

struct Curl_cftype Curl_cft_h2_proxy = {
  "H2-PROXY",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_h2_proxy_destroy,
  cf_h2_proxy_connect,
  cf_h2_proxy_close,
  Curl_cf_http_proxy_get_host,
  cf_h2_proxy_get_select_socks,
  cf_h2_proxy_data_pending,
  cf_h2_proxy_send,
  cf_h2_proxy_recv,
  Curl_cf_def_cntrl,
  cf_h2_proxy_is_alive,
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
