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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_PROXY) && \
  defined(USE_PROXY_HTTP3) && defined(USE_NGHTTP3) &&              \
  defined(USE_NGTCP2) && defined(USE_OPENSSL)

#include "urldata.h"
#include "url.h"
#include "curl_trc.h"
#include "sendf.h"
#include "multiif.h"
#include "cfilters.h"
#include "connect.h"
#include "progress.h"
#include "curlx/dynbuf.h"
#include "http_proxy.h"
#include "vquic/vquic.h"
#include "vquic/cf-ngtcp2-cmn.h"
#include "vquic/cf-ngtcp2-proxy.h"
#include "capsule.h"

/* A stream window is the maximum amount we need to buffer for
 * each active transfer. We use HTTP/3 flow control and only ACK
 * when we take things out of the buffer.
 * Chunk size is large enough to take a full DATA frame */
#define PROXY_H3_STREAM_RECV_CHUNKS ((512 * 1024) / H3_STREAM_CHUNK_SIZE)

typedef enum {
  H3_TUNNEL_INIT,     /* init/default/no tunnel state */
  H3_TUNNEL_CONNECT,  /* CONNECT request is being sent */
  H3_TUNNEL_RESPONSE, /* CONNECT response received completely */
  H3_TUNNEL_ESTABLISHED,
  H3_TUNNEL_FAILED
} h3_tunnel_state;

struct h3_tunnel_stream {
  struct Curl_peer *peer;  /* where the tunnel goes to */
  struct http_resp *resp;
  struct bufq recvbuf;
  char *authority;
  struct h3_stream_ctx *stream;
  h3_tunnel_state state;
  BIT(udp);
  BIT(has_final_response);
  BIT(closed);
};

static CURLcode h3_tunnel_stream_init(struct h3_tunnel_stream *ts,
                                      struct Curl_peer *peer,
                                      bool udp)
{
  ts->state = H3_TUNNEL_INIT;
  Curl_peer_link(&ts->peer, peer);
  Curl_bufq_init2(&ts->recvbuf, H3_STREAM_CHUNK_SIZE,
                  PROXY_H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
  ts->udp = udp;
  /* host:port with IPv6 support */
  ts->authority = curl_maprintf("%s%s%s:%u", peer->ipv6 ? "[" : "",
                                peer->hostname,
                                peer->ipv6 ? "]" : "",
                                peer->port);
  if(!ts->authority)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static void h3_tunnel_stream_reset(struct h3_tunnel_stream *ts)
{
  Curl_bufq_reset(&ts->recvbuf);
  Curl_http_resp_free(ts->resp);
  ts->resp = NULL;
  ts->stream = NULL;
  ts->has_final_response = FALSE;
  ts->closed = FALSE;
  ts->state = H3_TUNNEL_INIT;
}

static void h3_tunnel_stream_cleanup(struct h3_tunnel_stream *ts)
{
  Curl_peer_unlink(&ts->peer);
  Curl_bufq_free(&ts->recvbuf);
  Curl_http_resp_free(ts->resp);
  curlx_safefree(ts->authority);
  ts->state = H3_TUNNEL_INIT;
}

static void h3_tunnel_go_state(struct Curl_cfilter *cf,
                               struct h3_tunnel_stream *ts,
                               h3_tunnel_state new_state,
                               struct Curl_easy *data)
{
  VERBOSE(int64_t stream_id = ts->stream ? ts->stream->id : -1);
  (void)cf;

  if(ts->state == new_state)
    return;

  /* leaving this one */
  switch(ts->state) {
  case H3_TUNNEL_CONNECT:
    data->req.ignorebody = FALSE;
    break;
  default:
    break;
  }

  /* entering this one */
  switch(new_state) {
  case H3_TUNNEL_INIT:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] -> [init]", stream_id);
    h3_tunnel_stream_reset(ts);
    break;
  case H3_TUNNEL_CONNECT:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] -> [connect]", stream_id);
    ts->state = H3_TUNNEL_CONNECT;
    break;
  case H3_TUNNEL_RESPONSE:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] -> [response]", stream_id);
    ts->state = H3_TUNNEL_RESPONSE;
    break;
  case H3_TUNNEL_ESTABLISHED:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] -> [established]", stream_id);
    infof(data, "CONNECT%s phase completed for HTTP/3 proxy",
          ts->udp ? "-UDP" : "");
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    ts->state = new_state;
    curlx_safefree(data->req.hd_proxy_auth);
    break;
  case H3_TUNNEL_FAILED:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] -> [failed]", stream_id);
    ts->state = new_state;
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it is not accidentally used for the document request
       after we have connected. So let's free and clear it here. */
    curlx_safefree(data->req.hd_proxy_auth);
    break;
  }
}

struct cf_h3_proxy_ctx {
  struct cf_ngtcp2_ctx ngtcp2_ctx;
  struct h3_tunnel_stream tunnel; /* our tunnel CONNECT stream */
  BIT(connected);
};

static CURLcode cf_ngtcp2_proxy_h3_init(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct cf_ngtcp2_ctx *ctx);

static CURLcode cf_h3_proxy_ctx_init(struct cf_h3_proxy_ctx *ctx,
                                     struct Curl_peer *origin,
                                     struct Curl_peer *peer,
                                     struct ssl_primary_config *sslc,
                                     struct Curl_peer *tunnel_peer,
                                     uint8_t tunnel_transport)
{
  CURLcode result;
  result = Curl_cf_ngtcp2_ctx_init(&ctx->ngtcp2_ctx, origin, peer,
                                   sslc, cf_ngtcp2_proxy_h3_init);
  if(!result)
    result = h3_tunnel_stream_init(&ctx->tunnel, tunnel_peer,
                                   TRNSPRT_IS_DGRAM(tunnel_transport));
  return result;
}

static void cf_h3_proxy_ctx_free(struct cf_h3_proxy_ctx *ctx)
{
  if(ctx) {
    Curl_cf_ngtcp2_ctx_cleanup(&ctx->ngtcp2_ctx);
    h3_tunnel_stream_cleanup(&ctx->tunnel);
    curlx_free(ctx);
  }
}

static int cb_h3_proxy_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                      uint64_t datalen, void *user_data,
                                      void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct h3_stream_ctx *stream;
  size_t skiplen;
  (void)stream_user_data;

  stream = pctx->tunnel.stream;
  if(!stream || (stream->id != stream_id))
    return 0;

  /* The server acknowledged `datalen` of bytes from our request body.
   * This is a delta. We have kept this data in `sendbuf` for
   * re-transmissions and can free it now. */
  if(datalen >= (uint64_t)stream->sendbuf_len_in_flight)
    skiplen = stream->sendbuf_len_in_flight;
  else
    skiplen = (size_t)datalen;
  Curl_bufq_skip(&stream->sendbuf, skiplen);
  stream->sendbuf_len_in_flight -= skiplen;

  /* Resume upload processing if we have more data to send */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    int rv = nghttp3_conn_resume_stream(conn, stream_id);
    if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int cb_h3_proxy_stream_close(nghttp3_conn *conn, int64_t stream_id,
                                    uint64_t app_error_code, void *user_data,
                                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct h3_stream_ctx *stream;

  (void)conn;
  (void)stream_user_data;
  if(!data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  stream = pctx->tunnel.stream;
  if(!stream || (stream->id != stream_id))
    return 0;

  stream->closed = TRUE;
  stream->error3 = app_error_code;
  if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" PRId64 "] RESET: error %" PRIu64,
                stream->id, stream->error3);
  }
  else
    CURL_TRC_CF(data, cf, "[%" PRId64 "] CLOSED", stream->id);
  pctx->tunnel.stream = NULL;
  pctx->tunnel.closed = TRUE;
  Curl_multi_mark_dirty(data);
  return 0;
}

static void cf_h3_proxy_upd_rx_win(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_stream_ctx *stream)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  uint64_t cur_win, wanted_win = H3_STREAM_WINDOW_SIZE_MAX;

  /* how much does rate limiting allow us to acknowledge? */
  if(Curl_rlimit_active(&data->progress.dl.rlimit)) {
    int64_t avail;

    /* start rate limit updates only after first bytes arrived */
    if(!stream->rx_offset)
      return;

    avail = Curl_rlimit_avail(&data->progress.dl.rlimit, Curl_pgrs_now(data));
    if(avail <= 0) {
      /* nothing available, do not extend the rx offset */
      CURL_TRC_CF(data, cf, "[%" PRId64 "] dl rate limit exhausted (%" PRId64
                  " tokens)", stream->id, avail);
      return;
    }
    wanted_win = CURLMIN((uint64_t)avail, H3_STREAM_WINDOW_SIZE_MAX);
  }

  if(stream->rx_offset_max < stream->rx_offset) {
    DEBUGASSERT(0);
    return;
  }
  cur_win = stream->rx_offset_max - stream->rx_offset;
  if(cur_win < wanted_win) {
    /* We have exhausted the credit we gave the QUIC peer for DATA.
     * We extend it with the amount we can give (rate limit) */
    uint64_t ext = wanted_win - cur_win;

    ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream->id, ext);
    ngtcp2_conn_extend_max_offset(ctx->qconn, ext);
    stream->rx_offset_max += ext;
    if(stream->rx_offset_max > stream->window_size_max) {
      stream->window_size_max = stream->rx_offset_max;
      CURL_TRC_CF(data, cf, "[%" PRId64 "] max window now -> %" PRIu64,
                  stream->id, stream->window_size_max);
    }
    CURL_TRC_CF(data, cf, "[%" PRId64 "] rx_offset_max -> %" PRIu64
                " (ext %" PRIu64 ", win %" PRIu64 ")",
                stream->id, stream->rx_offset_max, ext, wanted_win);
  }
}

static int cb_h3_proxy_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                                 const uint8_t *buf, size_t buflen,
                                 void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct h3_stream_ctx *stream;
  size_t nwritten;
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)stream3_id;
  (void)stream_user_data;

  stream = pctx->tunnel.stream;
  if(!data || !stream || (stream->id != stream3_id)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  stream->rx_total += (curl_off_t)buflen;
  CURL_TRC_CF(data, cf, "[cb_h3_proxy_recv_data] "
              "[%" PRId64 "] DATA len=%zu, total=%" FMT_OFF_T,
              stream->id, buflen, stream->rx_total);

  result = Curl_bufq_write(&pctx->tunnel.recvbuf, buf, buflen, &nwritten);
  if(result || (nwritten < buflen)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  /* DATA has been moved into our local recv buffer. Update stream offsets
   * and give QUIC read credit back so long transfers over proxy tunnels
   * do not stall on stream/connection flow-control limits. */
  stream->rx_offset += buflen;
  if(stream->rx_offset_max < stream->rx_offset)
    stream->rx_offset_max = stream->rx_offset;

  CURL_TRC_CF(data, cf, "[%" PRId64 "] DATA len=%zu, rx win=%" PRIu64,
              stream->id, buflen, stream->rx_offset_max - stream->rx_offset);
  cf_h3_proxy_upd_rx_win(cf, data, stream);

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_proxy_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                        size_t consumed, void *user_data,
                                        void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  (void)conn;
  (void)stream_user_data;

  if(!ctx)
    return 0;

  /* nghttp3 has consumed bytes on the QUIC stream and we need to
   * tell the QUIC connection to increase its flow control */
  ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset(ctx->qconn, consumed);

  return 0;
}

static int cb_h3_proxy_recv_header(nghttp3_conn *conn, int64_t stream_id,
                                   int32_t token, nghttp3_rcbuf *name,
                                   nghttp3_rcbuf *value, uint8_t flags,
                                   void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct h3_stream_ctx *stream;
  CURLcode result = CURLE_OK;
  int http_status;
  struct http_resp *resp;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)stream_user_data;

  /* stream_user_data might be NULL for control streams */
  if(!data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  stream = pctx->tunnel.stream;
  if(!stream || (stream->id != stream_id)) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] recv_header: stream lookup "
                "failed for data=%p mid=%u",
                stream_id, (void *)data, data ? data->mid : 0);
    return 0;
  }

  if(pctx->tunnel.has_final_response) {
    /* we do not do anything with trailers for tunnel streams */
    return 0;
  }

  if(token == NGHTTP3_QPACK_TOKEN__STATUS) {
    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)h3val.base, h3val.len);
    if(result)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    http_status = stream->status_code;
    result = Curl_http_resp_make(&resp, http_status, NULL);
    if(result)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    if(pctx->tunnel.resp)
      Curl_http_resp_free(pctx->tunnel.resp);
    pctx->tunnel.resp = resp;
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" PRId64 "] header: %.*s: %.*s", stream_id,
                (int)h3name.len, h3name.base, (int)h3val.len, h3val.base);
    result = Curl_dynhds_add(&pctx->tunnel.resp->headers,
                             (const char *)h3name.base, h3name.len,
                             (const char *)h3val.base, h3val.len);
    if(result) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int cb_h3_proxy_end_headers(nghttp3_conn *conn, int64_t stream_id,
                                   int fin, void *user_data,
                                   void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct h3_stream_ctx *stream;
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)stream_user_data;

  if(!data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  stream = pctx->tunnel.stream;
  if(!stream || (stream->id != stream_id)) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] end_headers: stream lookup "
                "failed for data=%p mid=%u",
                stream_id, (void *)data, data ? data->mid : 0);
    return 0;
  }

  CURL_TRC_CF(data, cf, "[%" PRId64 "] end_headers, status=%d", stream_id,
              stream->status_code);

  if(!pctx->tunnel.has_final_response) {
    if(stream->status_code / 100 != 1) {
      pctx->tunnel.has_final_response = TRUE;
    }
  }

  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_proxy_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                                    uint64_t app_error_code, void *user_data,
                                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  (void)conn;
  (void)stream_user_data;

  if(ctx) {
    int rv = ngtcp2_conn_shutdown_stream_read(ctx->qconn, 0, stream_id,
                                              app_error_code);

    if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

static int cb_h3_proxy_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                                    uint64_t app_error_code, void *user_data,
                                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  int rv;

  (void)conn;
  (void)stream_user_data;
  if(!data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  if(!pctx->tunnel.stream ||
     (stream_id != pctx->tunnel.stream->id))
    return 0;

  rv = ngtcp2_conn_shutdown_stream_write(ctx->qconn, 0, stream_id,
                                         app_error_code);
  CURL_TRC_CF(data, cf, "[%" PRId64 "] reset -> %d", stream_id, rv);
  pctx->tunnel.stream = NULL;
  pctx->tunnel.closed = TRUE;
  if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static nghttp3_ssize cb_h3_tunnel_read_data(nghttp3_conn *conn,
                                            int64_t stream_id,
                                            nghttp3_vec *vec,
                                            size_t veccnt,
                                            uint32_t *pflags,
                                            void *user_data,
                                            void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct h3_stream_ctx *stream;
  size_t nwritten = 0;
  size_t nvecs = 0;
  const unsigned char *buf_base;

  (void)conn;
  (void)stream_id;
  (void)veccnt;
  (void)stream_user_data;
  (void)pflags;

  stream = pctx->tunnel.stream;
  if(!data || !stream || (stream->id != stream_id))
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  /* nghttp3 keeps references to the sendbuf data until it is ACKed
   * by the server (see `cb_h3_proxy_acked_req_body()` for updates).
   * `sendbuf_len_in_flight` is the amount of bytes in `sendbuf`
   * that we have already passed to nghttp3, but which have not been
   * ACKed yet.
   * Any amount beyond `sendbuf_len_in_flight` we need still to pass
   * to nghttp3. Do that now, if we can. */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    nvecs = 0;
    while(nvecs < veccnt) {
      if(!Curl_bufq_peek_at(&stream->sendbuf,
                           stream->sendbuf_len_in_flight,
                           &buf_base,
                           &vec[nvecs].len))
        break;
      vec[nvecs].base = (uint8_t *)(uintptr_t)buf_base;
      stream->sendbuf_len_in_flight += vec[nvecs].len;
      nwritten += vec[nvecs].len;
      ++nvecs;
    }
    DEBUGASSERT(nvecs > 0); /* we SHOULD have been able to peek */
  }

  if(!nwritten) {
    /* Not EOF, and nothing to give, we signal WOULDBLOCK. */
    CURL_TRC_CF(data, cf, "[%" PRId64 "] read req body -> AGAIN",
                stream->id);
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" PRId64 "] read req body -> "
              "%zu vecs%s with %zu (buffered=%zu)",
              stream->id, nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf));
  return (nghttp3_ssize)nvecs;
}

static nghttp3_callbacks ngh3_proxy_callbacks = {
  cb_h3_proxy_acked_req_body, /* acked_stream_data */
  cb_h3_proxy_stream_close,
  cb_h3_proxy_recv_data,
  cb_h3_proxy_deferred_consume,
  NULL, /* begin_headers */
  cb_h3_proxy_recv_header,
  cb_h3_proxy_end_headers,
  NULL, /* begin_trailers */
  cb_h3_proxy_recv_header,
  NULL, /* end_trailers */
  cb_h3_proxy_stop_sending,
  NULL, /* end_stream */
  cb_h3_proxy_reset_stream,
  NULL, /* shutdown */
  NULL, /* recv_settings (deprecated) */
#ifdef NGHTTP3_CALLBACKS_V2  /* nghttp3 v1.11.0+ */
  NULL, /* recv_origin */
  NULL, /* end_origin */
  NULL, /* rand */
#endif
#ifdef NGHTTP3_CALLBACKS_V3  /* nghttp3 v1.14.0+ */
  NULL, /* recv_settings2 */
#endif
};

static CURLcode cf_ngtcp2_proxy_h3_init(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct cf_ngtcp2_ctx *ctx)
{
  int rc;

  if(ngtcp2_conn_get_streams_uni_left(ctx->qconn) < 3) {
    failf(data, "QUIC connection lacks 3 uni streams to run HTTP/3");
    return CURLE_QUIC_CONNECT_ERROR;
  }

  nghttp3_settings_default(&ctx->h3settings);

  rc = nghttp3_conn_client_new(&ctx->h3conn,
                               &ngh3_proxy_callbacks,
                               &ctx->h3settings,
                               Curl_nghttp3_mem(),
                               cf);
  if(rc) {
    failf(data, "error creating nghttp3 connection instance");
    return CURLE_OUT_OF_MEMORY;
  }

  return Curl_cf_ngtcp2_h3_init_ctrls(ctx, data);
}

static ssize_t cf_h3_proxy_recv_closed_stream(struct Curl_cfilter *cf,
                                              struct Curl_easy *data,
                                              struct h3_stream_ctx *stream,
                                              CURLcode *err)
{
  ssize_t nread = -1;
  *err = CURLE_OK;

  if(stream->reset) {
    if(stream->error3 == CURL_H3_ERR_REQUEST_REJECTED) {
      infof(data, "HTTP/3 stream %" PRId64 " refused by server, try again "
            "on a new connection", stream->id);
      connclose(cf->conn, "REFUSED_STREAM");
      data->state.refused_stream = TRUE;
      *err = CURLE_RECV_ERROR;
      goto out;
    }
    else if(stream->resp_hds_complete && data->req.no_body) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] error after response headers, "
                  "but we did not want a body anyway, ignore error 0x%"
                  PRIx64 " %s", stream->id, stream->error3,
                  vquic_h3_err_str(stream->error3));
      nread = 0;
      goto out;
    }
    failf(data, "HTTP/3 stream %" PRId64 " reset by server (error 0x%" PRIx64
          " %s)", stream->id, stream->error3,
          vquic_h3_err_str(stream->error3));
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    goto out;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" PRId64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    *err = CURLE_HTTP3;
    goto out;
  }
  nread = 0;

out:
  return nread;
}

static CURLcode cf_h3_proxy_sendbuf_add(struct Curl_easy *data,
                                        struct h3_stream_ctx *stream,
                                        const uint8_t *buf, size_t len,
                                        size_t *pnwritten)
{
  CURLcode result;
  *pnwritten = 0;
  (void)data;

  result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
  return result;
}

static CURLcode cf_h3_proxy_send(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const uint8_t *buf, size_t len,
                                 bool eos, size_t *pnwritten)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  struct h3_stream_ctx *stream = NULL;
  struct cf_call_data save;
  struct cf_ngtcp2_io_ctx pktx;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  Curl_cf_ngtcp2_io_ctx_init(&pktx, cf, data);
  *pnwritten = 0;

  /* handshake verification failed in callback, do not send anything */
  if(ctx->tls_vrfy_result) {
    result = ctx->tls_vrfy_result;
    goto denied;
  }

  (void)eos; /* use for stream EOF and block handling */
  result = Curl_cf_ngtcp2_progress_ingress(cf, data, &pktx);
  if(result)
    goto out;

  if(pctx->tunnel.closed) {
    result = CURLE_SEND_ERROR;
    goto denied;
  }

  stream = pctx->tunnel.stream;
  if(!stream) {
    result = CURLE_SEND_ERROR;
    goto denied;
  }

  if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" PRId64 "] discarding data"
                  "on closed stream with response", stream->id);
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" PRId64 "] send_body(len=%zu) "
                "-> stream closed", stream->id, len);
    result = CURLE_HTTP3;
    goto out;
  }
  else {
    result = cf_h3_proxy_sendbuf_add(data, stream, buf, len, pnwritten);
    CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_send, add to "
                "sendbuf(len=%zu) -> %d, %zu",
                stream->id, len, (int)result, *pnwritten);
    if(result)
      goto out;
    (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
  }

  if(*pnwritten > 0 && !ctx->tls_handshake_complete && ctx->use_earlydata)
    ctx->earlydata_skip += *pnwritten;

  DEBUGASSERT(!result);
  result = Curl_cf_ngtcp2_progress_egress(cf, data, &pktx);

out:
  result = Curl_1st_fatal(result,
                          Curl_cf_ngtcp2_cmn_set_expiry(cf, data, &pktx));
denied:
  CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, (int)result, *pnwritten);
  CF_DATA_RESTORE(cf, save);
  return result;
}

/* incoming data frames on the h3 stream */
static CURLcode cf_h3_proxy_recv(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 char *buf, size_t len, size_t *pnread)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  struct h3_stream_ctx *stream = pctx->tunnel.stream;
  struct cf_call_data save;
  struct cf_ngtcp2_io_ctx pktx;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  *pnread = 0;

  /* handshake verification failed in callback, do not recv anything */
  if(ctx->tls_vrfy_result) {
    result = ctx->tls_vrfy_result;
    goto denied;
  }

  Curl_cf_ngtcp2_io_ctx_init(&pktx, cf, data);

  if(!stream || ctx->shutdown_started) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(!Curl_bufq_is_empty(&pctx->tunnel.recvbuf)) {
    result = Curl_bufq_cread(&pctx->tunnel.recvbuf, buf, len, pnread);
    if(result)
      goto out;
  }

  result = Curl_cf_ngtcp2_progress_ingress(cf, data, &pktx);
  if(result)
    goto out;

  /* inbufq had nothing before, maybe after progressing ingress? */
  if(!*pnread && !Curl_bufq_is_empty(&pctx->tunnel.recvbuf)) {
    result = Curl_bufq_cread(&pctx->tunnel.recvbuf, buf, len, pnread);
    if(result) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] read inbufq(len=%zu) -> %zu, %d",
                  stream->id, len, *pnread, (int)result);
      goto out;
    }
  }

  if(*pnread) {
    Curl_multi_mark_dirty(data);
  }
  else {
    if(stream->xfer_result) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] xfer write failed", stream->id);
      Curl_cf_ngtcp2_h3_stream_close(cf, data, stream);
      result = stream->xfer_result;
      goto out;
    }
    else if(stream->closed) {
      ssize_t nread =
        cf_h3_proxy_recv_closed_stream(cf, data, stream, &result);
      if(nread > 0)
        *pnread = (size_t)nread;
      goto out;
    }
    result = CURLE_AGAIN;
  }

out:
  result = Curl_1st_fatal(result,
                          Curl_cf_ngtcp2_progress_egress(cf, data, &pktx));
  result = Curl_1st_fatal(result,
                          Curl_cf_ngtcp2_cmn_set_expiry(cf, data, &pktx));
denied:
  CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_recv(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, (int)result, *pnread);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode cf_h3_proxy_submit(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_tunnel_stream *ts,
                                   struct httpreq *req)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  struct h3_stream_ctx *stream = NULL;
  struct dynhds h2_headers;
  nghttp3_nv *nva = NULL;
  size_t nheader;
  int rc = 0;
  unsigned int i;
  nghttp3_data_reader reader;
  nghttp3_data_reader *preader = NULL;
  CURLcode result;

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);
  result = Curl_http_req_to_h2(&h2_headers, req, data);
  if(result)
    goto out;

  result = Curl_cf_ngtcp2_h3_stream_setup(cf, data);
  if(result)
    goto out;
  stream = H3_STREAM_CTX(ctx, data);
  DEBUGASSERT(stream);
  if(!stream) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  nheader = Curl_dynhds_count(&h2_headers);
  nva = curlx_malloc(sizeof(nghttp3_nv) * nheader);
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
    nva[i].flags = NGHTTP3_NV_FLAG_NONE;
  }

  /* Open a bidirectional stream */
  {
    int64_t sid;
    int rv;

    DEBUGASSERT(stream->id == -1);
    /* Do NOT set `data` as stream user data. The transfer `data` may
     * get cleaned up long before the tunnel goes down. */
    rv = ngtcp2_conn_open_bidi_stream(ctx->qconn, &sid, NULL);
    if(rv) {
      failf(data, "cannot get bidi streams: %s", ngtcp2_strerror(rv));
      result = CURLE_SEND_ERROR;
      goto out;
    }
    stream->id = sid;
    ts->stream = stream;
    ++ctx->used_bidi_streams;
    CURL_TRC_CF(data, cf, "[%" PRId64 "] opened bidi stream", sid);
  }

  /* CONNECT-UDP request stream remains open for capsules, no fixed EOF. */
  stream->send_closed = 0;
  reader.read_data = cb_h3_tunnel_read_data;
  preader = &reader;

  rc = nghttp3_conn_submit_request(ctx->h3conn, stream->id,
                                   nva, nheader, preader, data);

  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%" PRId64 "] failed to send, "
                  "connection is closing", stream->id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" PRId64 "] failed to send -> %d (%s)",
                  stream->id, rc, nghttp3_strerror(rc));
      break;
    }
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    CURL_TRC_CF(data, cf, "[H3-PROXY] [%" PRId64 "] OPENED stream "
                "for %s", stream->id,
                Curl_bufref_ptr(&data->state.url));
  }

out:
  curlx_free(nva);
  Curl_dynhds_free(&h2_headers);
  return result;
}

static CURLcode cf_h3_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct easy_pollset *ps)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = &pctx->ngtcp2_ctx;
  bool want_recv, want_send;
  CURLcode result = CURLE_OK;
  curl_socket_t sock = (ctx->q.sockfd != CURL_SOCKET_BAD) ?
   ctx->q.sockfd : Curl_conn_cf_get_socket(cf, data);

  if(!ctx->qconn || !pctx->tunnel.stream || (sock == CURL_SOCKET_BAD))
    return CURLE_OK;

  Curl_pollset_check(data, ps, sock, &want_recv, &want_send);

  if(want_recv || want_send || !Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    struct h3_stream_ctx *stream = pctx->tunnel.stream;
    bool c_exhaust, s_exhaust;

    c_exhaust = want_send &&
                (!ngtcp2_conn_get_cwnd_left(ctx->qconn) ||
                 !ngtcp2_conn_get_max_data_left(ctx->qconn));
    s_exhaust = want_send && stream && stream->id >= 0 &&
                stream->quic_flow_blocked;
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                 !Curl_bufq_is_empty(&ctx->q.sendbuf);

    result = Curl_pollset_set(data, ps, sock, want_recv, want_send);
  }
  return result;
}

static bool cf_h3_proxy_data_pending(struct Curl_cfilter *cf,
                                     const struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  if(!Curl_bufq_is_empty(&pctx->tunnel.recvbuf))
    return TRUE;
  return cf->next ?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

static CURLcode cf_h3_proxy_submit_CONNECT(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct h3_tunnel_stream *ts)
{
  CURLcode result;
  struct httpreq *req = NULL;

  result = Curl_http_proxy_create_tunnel_request(&req, cf, data,
                                                  ts->peer,
                                                  PROXY_HTTP_V3,
                                                  (bool)ts->udp);
  if(!result)
    result = Curl_creader_set_null(data);
  if(!result)
    result = cf_h3_proxy_submit(cf, data, ts, req);

  if(req)
    Curl_http_req_free(req);
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  return result;
}

static CURLcode cf_h3_proxy_inspect_response(struct Curl_cfilter *cf,
                                             struct Curl_easy *data,
                                             struct h3_tunnel_stream *ts)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  proxy_inspect_result res;
  CURLcode result;

  result = Curl_http_proxy_inspect_tunnel_response(
      cf, data, ts->resp, (bool)pctx->tunnel.udp, &res);
  if(result)
    return result;
  switch(res) {
  case PROXY_INSPECT_OK:
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
    break;
  case PROXY_INSPECT_FAILED:
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
    result = CURLE_COULDNT_CONNECT;
    break;
  case PROXY_INSPECT_AUTH_RETRY:
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_INIT, data);
    break;
  }
  return result;
}

static CURLcode cf_h3_proxy_tunnel(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_tunnel_stream *ts,
                                   bool *pdone)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(ts);
  DEBUGASSERT(ts->authority);
  *pdone = FALSE;
  do {
    switch(ts->state) {
    case H3_TUNNEL_INIT:
      CURL_TRC_CF(data, cf, "[0] CONNECT start for %s", ts->authority);
      result = cf_h3_proxy_submit_CONNECT(cf, data, ts);
      if(result)
        goto out;
      h3_tunnel_go_state(cf, ts, H3_TUNNEL_CONNECT, data);

      result = Curl_cf_ngtcp2_progress_egress(cf, data, NULL);
      if(result)
        goto out;
      FALLTHROUGH();

    case H3_TUNNEL_CONNECT:
      /* Non-blocking: call ingress/egress once and return.
       * The multi interface will call us again when ready. */
      result = Curl_cf_ngtcp2_progress_ingress(cf, data, NULL);
      if(result)
        goto out;
      result = Curl_cf_ngtcp2_progress_egress(cf, data, NULL);
      if(result && result != CURLE_AGAIN) {
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
        goto out;
      }

      if(ts->has_final_response) {
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_RESPONSE, data);
      }
      else {
        /* Not done yet, return and let multi interface call us again */
        result = CURLE_OK;
        goto out;
      }
      FALLTHROUGH();

    case H3_TUNNEL_RESPONSE:
      DEBUGASSERT(ts->has_final_response);
      result = cf_h3_proxy_inspect_response(cf, data, ts);
      if(result)
        goto out;
      ctx->connected = TRUE;
      break;

    case H3_TUNNEL_ESTABLISHED:
      *pdone = TRUE;
      return CURLE_OK;

    case H3_TUNNEL_FAILED:
      return CURLE_RECV_ERROR;

    default:
      break;
    }

  } while(ts->state == H3_TUNNEL_INIT);

out:
  if((result && (result != CURLE_AGAIN)) || ctx->tunnel.closed)
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
  return result;
}

static CURLcode cf_h3_proxy_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data, bool *done)
{
  struct cf_h3_proxy_ctx *pctx = cf->ctx;
  struct cf_call_data save = { 0 };
  CURLcode result = CURLE_OK;
  struct h3_tunnel_stream *ts = &pctx->tunnel;
  bool data_saved = FALSE;

  result = Curl_cf_ngtcp2_cmn_connect(cf, data, done);
  if(result || !*done)
    goto out;

  CF_DATA_SAVE(save, cf, data);
  data_saved = TRUE;

  /* At this point the QUIC is connected, but the proxy is not connected */
  result = cf_h3_proxy_tunnel(cf, data, ts, done);

out:
  if(*done) {
    cf->connected = TRUE;
    /* The real request will follow the CONNECT, reset request partially */
    Curl_req_soft_reset(&data->req, data);
    Curl_client_reset(data);
  }

  if(data_saved)
    CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_h3_proxy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    CURL_TRC_CF(data, cf, "cf_h3_proxy_destroy()");
    cf_h3_proxy_ctx_free(ctx);
    cf->ctx = NULL;
  }
}

static CURLcode cf_h3_proxy_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data, bool *done)
{
  return Curl_cf_ngtcp2_cmn_shutdown(cf, data, done);
}

struct Curl_cftype Curl_cft_h3_proxy = {
  "H3-PROXY",
  CF_TYPE_IP_CONNECT | CF_TYPE_PROXY | CF_TYPE_SSL,
  CURL_LOG_LVL_NONE,
  cf_h3_proxy_destroy,
  cf_h3_proxy_connect,
  cf_h3_proxy_shutdown,
  cf_h3_proxy_adjust_pollset,
  cf_h3_proxy_data_pending,
  cf_h3_proxy_send,
  cf_h3_proxy_recv,
  Curl_cf_def_cntrl,
  Curl_cf_ngtcp2_cmn_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

CURLcode Curl_cf_ngtcp2_proxy_create(struct Curl_cfilter **pcf,
                                     struct Curl_easy *data,
                                     struct Curl_peer *origin,
                                     struct Curl_peer *peer,
                                     uint8_t transport_peer,
                                     struct connectdata *conn,
                                     struct Curl_sockaddr_ex *addr,
                                     struct Curl_peer *tunnel_peer,
                                     uint8_t tunnel_transport)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_h3_proxy_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  if(!tunnel_peer)
    return CURLE_FAILED_INIT;
  if((transport_peer != TRNSPRT_QUIC) || (!conn->http_proxy.peer))
    return CURLE_FAILED_INIT;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  result = cf_h3_proxy_ctx_init(ctx, origin, peer, &conn->proxy_ssl_config,
                                tunnel_peer, tunnel_transport);
  if(result)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_h3_proxy, ctx);
  if(result)
    goto out;
  cf->conn = conn;

  result = Curl_cf_udp_create(&cf->next, data, origin, peer, TRNSPRT_QUIC,
                              conn, addr, NULL, TRNSPRT_QUIC);
  if(result)
    goto out;
  cf->next->conn = cf->conn;
  cf->next->sockindex = cf->sockindex;

out:
  *pcf = (!result) ? cf : NULL;
  if(result) {
    if(cf)
      Curl_conn_cf_discard_chain(&cf, data);
    else if(ctx)
      cf_h3_proxy_ctx_free(ctx);
  }
  else
    CURL_TRC_CF(data, cf, "created, udp_tunnel=%d", ctx->tunnel.udp);
  return result;
}

CURLcode Curl_cf_ngtcp2_proxy_insert_after(struct Curl_cfilter *cf_at,
                                           struct Curl_easy *data,
                                           struct Curl_peer *origin,
                                           struct Curl_peer *peer,
                                           struct Curl_peer *tunnel_peer,
                                           uint8_t tunnel_transport)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_h3_proxy_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  (void)data;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;
  result = cf_h3_proxy_ctx_init(ctx, origin, peer,
                                &cf_at->conn->proxy_ssl_config,
                                tunnel_peer, tunnel_transport);
  if(result)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_h3_proxy, ctx);
  if(result)
    goto out;

  /* H3-PROXY uses the UDP socket created by happy eyeballs below it.
     Curl_conn_cf_insert_after chains the existing sub-filters, i.e.
     "HAPPY-EYEBALLS -> UDP" as cf->next of H3-PROXY. */
  Curl_conn_cf_insert_after(cf_at, cf);

out:
  if(result) {
    if(cf)
      Curl_conn_cf_discard_chain(&cf, data);
    else if(ctx)
      cf_h3_proxy_ctx_free(ctx);
  }
  return result;
}

#endif
