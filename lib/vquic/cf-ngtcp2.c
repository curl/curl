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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGTCP2) && defined(USE_NGHTTP3)

#include "urldata.h"
#include "url.h"
#include "uint-hash.h"
#include "curl_trc.h"
#include "rand.h"
#include "multiif.h"
#include "cfilters.h"
#include "cf-dns.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "curlx/fopen.h"
#include "curlx/dynbuf.h"
#include "http1.h"
#include "select.h"
#include "transfer.h"
#include "bufref.h"
#include "vquic/vquic.h"
#include "vquic/vquic_int.h"
#include "vquic/cf-ngtcp2-cmn.h"
#include "vquic/cf-ngtcp2.h"


static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *user_data,
                                void *stream_user_data);

static CURLcode cf_ngtcp2_adjust_pollset(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct easy_pollset *ps)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  bool want_recv, want_send;
  CURLcode result = CURLE_OK;
  curl_socket_t sock = (ctx->q.sockfd != CURL_SOCKET_BAD) ?
   ctx->q.sockfd : Curl_conn_cf_get_socket(cf, data);

  if(!ctx->qconn || (sock == CURL_SOCKET_BAD))
    return CURLE_OK;

  Curl_pollset_check(data, ps, sock, &want_recv, &want_send);
  if(!want_send && !Curl_bufq_is_empty(&ctx->q.sendbuf))
    want_send = TRUE;

  if(want_recv || want_send) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    struct cf_call_data save;
    bool c_exhaust, s_exhaust;

    CF_DATA_SAVE(save, cf, data);
    c_exhaust = want_send && (!ngtcp2_conn_get_cwnd_left(ctx->qconn) ||
                              !ngtcp2_conn_get_max_data_left(ctx->qconn));
    s_exhaust = want_send && stream && stream->id >= 0 &&
                stream->quic_flow_blocked;
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                 !Curl_bufq_is_empty(&ctx->q.sendbuf);

    result = Curl_pollset_set(data, ps, sock, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
  return result;
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;

  /* we might be called by nghttp3 after we already cleaned up */
  if(!stream)
    return 0;

  stream->closed = TRUE;
  stream->error3 = app_error_code;
  if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" PRId64 "] RESET: error %" PRIu64,
                stream->id, stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] CLOSED", stream->id);
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

static void h3_xfer_write_resp_hd(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream,
                                  const char *buf, size_t buflen, bool eos)
{
  /* This function returns no error intentionally, but records
   * the result at the stream, skipping further writes once the
   * `result` of the transfer is known.
   * The stream is subsequently cancelled "higher up" in the filter's
   * send/recv callbacks. Closing the stream here leads to SEND/RECV
   * errors in other places that then overwrite the transfer's result. */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp_hd(data, buf, buflen, eos);
    if(stream->xfer_result)
      CURL_TRC_CF(data, cf, "[%" PRId64 "] error %d writing %zu "
                  "bytes of headers", stream->id, (int)stream->xfer_result,
                  buflen);
  }
}

static void h3_xfer_write_resp(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h3_stream_ctx *stream,
                               const char *buf, size_t buflen, bool eos)
{
  /* This function returns no error intentionally, but records
   * the result at the stream, skipping further writes once the
   * `result` of the transfer is known.
   * The stream is subsequently cancelled "higher up" in the filter's
   * send/recv callbacks. Closing the stream here leads to SEND/RECV
   * errors in other places that then overwrite the transfer's result. */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp(data, buf, buflen, eos);
    /* If the transfer write is errored, we do not want any more data */
    if(stream->xfer_result) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] error %d writing %zu bytes of data",
                  stream->id, (int)stream->xfer_result, buflen);
    }
  }
}

static void cf_ngtcp2_upd_rx_win(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct h3_stream_ctx *stream)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  uint64_t cur_win, wanted_win = H3_STREAM_WINDOW_SIZE_MAX;

  /* how much does rate limiting allow us to acknowledge? */
  if(Curl_rlimit_active(&data->progress.dl.rlimit)) {
    int64_t avail;

    /* start rate limit updates only after first bytes arrived */
    if(!stream->rx_offset)
      return;

    avail = Curl_rlimit_avail(&data->progress.dl.rlimit, NULL);
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

  if(wanted_win > cur_win) {
    uint64_t delta = wanted_win - cur_win;

    if(UINT64_MAX - delta < stream->rx_offset_max)
      delta = UINT64_MAX - stream->rx_offset_max;
    if(delta) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] rx window, extend by %" PRIu64
                  " bytes", stream->id, delta);
      stream->rx_offset_max += delta;
      ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream->id, delta);
    }
  }
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t buflen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  (void)conn;
  (void)stream3_id;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  h3_xfer_write_resp(cf, data, stream, (const char *)buf, buflen, FALSE);

  ngtcp2_conn_extend_max_offset(ctx->qconn, buflen);
  stream->rx_offset += buflen;
  if(stream->rx_offset_max < stream->rx_offset)
    stream->rx_offset_max = stream->rx_offset;

  CURL_TRC_CF(data, cf, "[%" PRId64 "] DATA len=%zu, rx win=%" PRIu64,
              stream->id, buflen, stream->rx_offset_max - stream->rx_offset);
  cf_ngtcp2_upd_rx_win(cf, data, stream);
  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream3_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;

  /* nghttp3 has consumed bytes on the QUIC stream and we need to
   * tell the QUIC connection to increase its flow control */
  ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream3_id, consumed);
  ngtcp2_conn_extend_max_offset(ctx->qconn, consumed);
  if(stream) {
    stream->rx_offset += consumed;
    stream->rx_offset_max += consumed;
  }
  return 0;
}

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t stream_id,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)cf;

  if(!stream)
    return 0;
  /* add a CRLF only if we have received some headers */
  h3_xfer_write_resp_hd(cf, data, stream, STRCONST("\r\n"),
                        (bool)stream->closed);

  CURL_TRC_CF(data, cf, "[%" PRId64 "] end_headers, status=%d",
              stream_id, stream->status_code);
  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)cf;

  /* we might have cleaned up this transfer already */
  if(!stream)
    return 0;

  if(token == NGHTTP3_QPACK_TOKEN__STATUS) {

    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)h3val.base, h3val.len);
    if(result)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    curlx_dyn_reset(&ctx->scratch);
    result = curlx_dyn_addn(&ctx->scratch, STRCONST("HTTP/3 "));
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch,
                              (const char *)h3val.base, h3val.len);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST(" \r\n"));
    if(!result)
      h3_xfer_write_resp_hd(cf, data, stream, curlx_dyn_ptr(&ctx->scratch),
                            curlx_dyn_len(&ctx->scratch), FALSE);
    CURL_TRC_CF(data, cf, "[%" PRId64 "] status: %s",
                stream_id, curlx_dyn_ptr(&ctx->scratch));
    if(result) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" PRId64 "] header: %.*s: %.*s",
                stream_id, (int)h3name.len, h3name.base,
                (int)h3val.len, h3val.base);
    curlx_dyn_reset(&ctx->scratch);
    result = curlx_dyn_addn(&ctx->scratch,
                            (const char *)h3name.base, h3name.len);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST(": "));
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch,
                              (const char *)h3val.base, h3val.len);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST("\r\n"));
    if(!result)
      h3_xfer_write_resp_hd(cf, data, stream, curlx_dyn_ptr(&ctx->scratch),
                            curlx_dyn_len(&ctx->scratch), FALSE);
  }
  return 0;
}

static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rv;
  (void)conn;
  (void)stream_user_data;

  rv = ngtcp2_conn_shutdown_stream_read(ctx->qconn, 0, stream_id,
                                        app_error_code);
  if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)conn;

  rv = ngtcp2_conn_shutdown_stream_write(ctx->qconn, 0, stream_id,
                                         app_error_code);
  CURL_TRC_CF(data, cf, "[%" PRId64 "] reset -> %d", stream_id, rv);
  if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  NULL, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  NULL, /* begin_trailers */
  cb_h3_recv_header,
  NULL, /* end_trailers */
  cb_h3_stop_sending,
  NULL, /* end_stream */
  cb_h3_reset_stream,
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

static CURLcode init_ngh3_conn(struct Curl_cfilter *cf,
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
                               &ngh3_callbacks,
                               &ctx->h3settings,
                               Curl_nghttp3_mem(),
                               cf);
  if(rc) {
    failf(data, "error creating nghttp3 connection instance");
    return CURLE_OUT_OF_MEMORY;
  }

  return Curl_cf_ngtcp2_h3_init_ctrls(ctx, data);
}

static CURLcode recv_closed_stream(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_stream_ctx *stream,
                                   size_t *pnread)
{
  (void)cf;
  *pnread = 0;
  if(stream->reset) {
    if(stream->error3 == CURL_H3_ERR_REQUEST_REJECTED) {
      infof(data, "HTTP/3 stream %" PRId64 " refused by server, try again "
            "on a new connection", stream->id);
      connclose(cf->conn); /* do not use this anymore */
      data->state.refused_stream = TRUE;
      return CURLE_RECV_ERROR; /* trigger Curl_retry_request() later */
    }
    else if(stream->resp_hds_complete && data->req.no_body) {
        CURL_TRC_CF(data, cf, "[%" PRId64 "] error after response headers, "
                    "but we did not want a body anyway, ignore error 0x%"
                    PRIx64 " %s", stream->id, stream->error3,
                    Curl_vquic_h3_err_str(stream->error3));
        return CURLE_OK;
    }
    failf(data, "HTTP/3 stream %" PRId64 " reset by server (error 0x%" PRIx64
          " %s)", stream->id, stream->error3,
          Curl_vquic_h3_err_str(stream->error3));
    return data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" PRId64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    return CURLE_HTTP3;
  }
  return CURLE_OK;
}

/* incoming data frames on the h3 stream */
static CURLcode cf_ngtcp2_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                               char *buf, size_t buflen, size_t *pnread)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  struct cf_ngtcp2_io_ctx pktx;
  CURLcode result = CURLE_OK;
  int i;

  (void)ctx;
  (void)buf;
  NOVERBOSE((void)buflen);

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

  cf_ngtcp2_upd_rx_win(cf, data, stream);

  /* first check for results/closed already known without touching
   * the connection. For an already failed/closed stream, errors on
   * the connection do not count.
   * Then handle incoming data and check for failed/closed again.
   */
  for(i = 0; i < 2; ++i) {
    if(stream->xfer_result) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] xfer write failed", stream->id);
      Curl_cf_ngtcp2_h3_stream_close(cf, data, stream);
      result = stream->xfer_result;
      goto out;
    }
    else if(stream->closed) {
      result = recv_closed_stream(cf, data, stream, pnread);
      goto out;
    }

    if(!i && Curl_cf_ngtcp2_progress_ingress(cf, data, &pktx)) {
      result = CURLE_RECV_ERROR;
      goto out;
    }
  }

  result = CURLE_AGAIN;

out:
  result = Curl_1st_fatal(result,
                          Curl_cf_ngtcp2_progress_egress(cf, data, &pktx));
  result = Curl_1st_fatal(result,
                          Curl_cf_ngtcp2_cmn_set_expiry(cf, data, &pktx));
  if(ctx->tls_vrfy_result)
    result = ctx->tls_vrfy_result;
denied:
  CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_recv(buflen=%zu) -> %d, %zu",
              stream ? stream->id : -1, buflen, (int)result, *pnread);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *user_data,
                                void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t skiplen;

  (void)cf;
  if(!stream)
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

static nghttp3_ssize cb_h3_read_req_body(nghttp3_conn *conn, int64_t stream_id,
                                         nghttp3_vec *vec, size_t veccnt,
                                         uint32_t *pflags, void *user_data,
                                         void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t nwritten = 0;
  size_t nvecs = 0;
  (void)cf;
  (void)conn;
  (void)stream_id;
  (void)user_data;
  (void)veccnt;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  /* nghttp3 keeps references to the sendbuf data until it is ACKed
   * by the server (see `cb_h3_acked_req_body()` for updates).
   * `sendbuf_len_in_flight` is the amount of bytes in `sendbuf`
   * that we have already passed to nghttp3, but which have not been
   * ACKed yet.
   * Any amount beyond `sendbuf_len_in_flight` we need still to pass
   * to nghttp3. Do that now, if we can. */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    nvecs = 0;
    while(nvecs < veccnt &&
          Curl_bufq_peek_at(&stream->sendbuf,
                            stream->sendbuf_len_in_flight,
                            CURL_UNCONST(&vec[nvecs].base),
                            &vec[nvecs].len)) {
      stream->sendbuf_len_in_flight += vec[nvecs].len;
      nwritten += vec[nvecs].len;
      ++nvecs;
    }
    DEBUGASSERT(nvecs > 0); /* we SHOULD have been be able to peek */
  }

  if(nwritten > 0 && stream->upload_left != -1)
    stream->upload_left -= nwritten;

  /* When we stopped sending and everything in `sendbuf` is "in flight",
   * we are at the end of the request body. */
  if(stream->upload_left == 0) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }
  else if(!nwritten) {
    /* Not EOF, and nothing to give, we signal WOULDBLOCK. */
    CURL_TRC_CF(data, cf, "[%" PRId64 "] read req body -> AGAIN", stream->id);
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" PRId64 "] read req body -> "
              "%zu vecs%s with %zu (buffered=%zu, left=%" FMT_OFF_T ")",
              stream->id, nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf),
              stream->upload_left);
  return (nghttp3_ssize)nvecs;
}

static CURLcode h3_stream_open(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const uint8_t *buf, size_t len,
                               size_t *pnwritten)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
  int64_t sid;
  struct dynhds h2_headers;
  size_t nheader;
  nghttp3_nv *nva = NULL;
  int rc = 0;
  unsigned int i;
  nghttp3_data_reader reader;
  nghttp3_data_reader *preader = NULL;
  CURLcode result;

  *pnwritten = 0;
  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  result = Curl_cf_ngtcp2_h3_stream_setup(cf, data);
  if(result)
    goto out;
  stream = H3_STREAM_CTX(ctx, data);
  DEBUGASSERT(stream);
  if(!stream) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  result = Curl_h1_req_parse_read(&stream->h1, buf, len, NULL,
                                  !data->state.http_ignorecustom ?
                                  data->set.str[STRING_CUSTOMREQUEST] : NULL,
                                  0, pnwritten);
  if(result)
    goto out;
  if(!stream->h1.done) {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  result = Curl_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if(result)
    goto out;

  /* no longer needed */
  Curl_h1_req_parse_free(&stream->h1);

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

  rc = ngtcp2_conn_open_bidi_stream(ctx->qconn, &sid, data);
  if(rc) {
    failf(data, "cannot open bidi streams");
    result = CURLE_SEND_ERROR;
    goto out;
  }
  stream->id = sid;
  ++ctx->used_bidi_streams;

  switch(data->state.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
  case HTTPREQ_PUT:
    /* known request body size or -1 */
    if(data->state.infilesize != -1)
      stream->upload_left = data->state.infilesize;
    else
      /* data sending without specifying the data amount up front */
      stream->upload_left = -1; /* unknown */
    break;
  default:
    /* there is no request body */
    stream->upload_left = 0; /* no request body */
    break;
  }

  stream->send_closed = (stream->upload_left == 0);
  if(!stream->send_closed) {
    reader.read_data = cb_h3_read_req_body;
    preader = &reader;
  }

  rc = nghttp3_conn_submit_request(ctx->h3conn, stream->id,
                                   nva, nheader, preader, data);
  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%" PRId64 "] failed to send, "
                  "connection is closing", stream->id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" PRId64 "] failed to send -> "
                  "%d (%s)", stream->id, rc, nghttp3_strerror(rc));
      break;
    }
    Curl_cf_ngtcp2_h3_stream_close(cf, data, stream);
    result = CURLE_SEND_ERROR;
    goto out;
  }

  cf_ngtcp2_upd_rx_win(cf, data, stream);

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" PRId64 "] OPENED stream for %s",
          stream->id, Curl_bufref_ptr(&data->state.url));
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" PRId64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].namelen, nva[i].name,
            (int)nva[i].valuelen, nva[i].value);
    }
  }

out:
  curlx_free(nva);
  Curl_dynhds_free(&h2_headers);
  return result;
}

static CURLcode cf_ngtcp2_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                               const uint8_t *buf, size_t len, bool eos,
                               size_t *pnwritten)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
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

  if(!stream || stream->id < 0) {
    if(ctx->shutdown_started) {
      CURL_TRC_CF(data, cf, "cannot open stream on closed connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }
    result = h3_stream_open(cf, data, buf, len, pnwritten);
    if(result) {
      CURL_TRC_CF(data, cf, "failed to open stream -> %d", (int)result);
      goto out;
    }
    VERBOSE(stream = H3_STREAM_CTX(ctx, data));
  }
  else if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] xfer write failed", stream->id);
    Curl_cf_ngtcp2_h3_stream_close(cf, data, stream);
    result = stream->xfer_result;
    goto out;
  }
  else if(stream->closed) {
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
  else if(ctx->shutdown_started) {
    CURL_TRC_CF(data, cf, "cannot send on closed connection");
    result = CURLE_SEND_ERROR;
    goto out;
  }
  else {
    result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
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
  if(ctx->tls_vrfy_result)
    result = ctx->tls_vrfy_result;
denied:
  CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, (int)result, *pnwritten);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  /* There seems to exist no API in ngtcp2 to shrink/enlarge the streams
   * windows. As we do in HTTP/2. */
  (void)cf;
  if(!pause)
    Curl_multi_mark_dirty(data);
  return CURLE_OK;
}

static CURLcode cf_ngtcp2_cntrl(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int event, int arg1, void *arg2)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    Curl_cf_ngtcp2_h3_stream_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(stream && !stream->send_closed) {
      stream->send_closed = TRUE;
      stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
        stream->sendbuf_len_in_flight;
      (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
    }
    break;
  }
  case CF_CTRL_CONN_INFO_UPDATE:
    if(!cf->sockindex && cf->connected) {
      cf->conn->httpversion_seen = 30;
      Curl_conn_set_multiplex(cf->conn);
    }
    break;
  default:
    break;
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_ngtcp2_ctx_close(struct cf_ngtcp2_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(!ctx->initialized)
    return;
  if(ctx->qlogfd != -1) {
    curlx_close(ctx->qlogfd);
  }
  ctx->qlogfd = -1;
  Curl_vquic_tls_cleanup(&ctx->tls);
  Curl_ssl_peer_cleanup(&ctx->ssl_peer);
  Curl_vquic_ctx_free(&ctx->q);
  if(ctx->h3conn) {
    nghttp3_conn_del(ctx->h3conn);
    ctx->h3conn = NULL;
  }
  if(ctx->qconn) {
    ngtcp2_conn_del(ctx->qconn);
    ctx->qconn = NULL;
  }
#ifdef OPENSSL_QUIC_API2
  if(ctx->ossl_ctx) {
    ngtcp2_crypto_ossl_ctx_del(ctx->ossl_ctx);
    ctx->ossl_ctx = NULL;
  }
#endif
  ctx->call_data = save;
}

static void cf_ngtcp2_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  if(ctx) {
    if(ctx->qconn) {
      struct cf_call_data save;
      CF_DATA_SAVE(save, cf, data);
      Curl_cf_ngtcp2_cmn_conn_close(cf, data);
      cf_ngtcp2_ctx_close(ctx);
      CF_DATA_RESTORE(cf, save);
    }
    Curl_cf_ngtcp2_ctx_cleanup(ctx);
    curlx_free(ctx);
    cf->ctx = NULL;
  }
}

static CURLcode cf_ngtcp2_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done)
{
  return Curl_cf_ngtcp2_cmn_connect(cf, data, done);
}

static CURLcode cf_ngtcp2_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int query, int *pres1, void *pres2)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    DEBUGASSERT(pres1);
    CF_DATA_SAVE(save, cf, data);
    /* Set after transport params arrived and continually updated
     * by callback. QUIC counts the number over the lifetime of the
     * connection, ever increasing.
     * We count the *open* transfers plus the budget for new ones. */
    if(!ctx->qconn || ctx->shutdown_started) {
      *pres1 = 0;
    }
    else if(ctx->max_bidi_streams) {
      uint64_t avail_bidi_streams = 0;
      uint64_t max_streams = cf->conn->attached_xfers;
      if(ctx->max_bidi_streams > ctx->used_bidi_streams)
        avail_bidi_streams = ctx->max_bidi_streams - ctx->used_bidi_streams;
      max_streams += avail_bidi_streams;
      *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    }
    else  /* transport params not arrived yet? take our default. */
      *pres1 = (int)Curl_multi_max_concurrent_streams(data->multi);
    CURL_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%u in use)",
                cf->conn->connection_id, *pres1, cf->conn->attached_xfers);
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->q.got_first_byte) {
      timediff_t ms = curlx_ptimediff_ms(&ctx->q.first_byte_at,
                                         &ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->q.got_first_byte)
      *when = ctx->q.first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 30;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO: {
    struct curl_tlssessioninfo *info = pres2;
    if(Curl_vquic_tls_get_ssl_info(&ctx->tls,
                                   (query == CF_QUERY_SSL_CTX_INFO), info))
      return CURLE_OK;
    break;
  }
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = cf->connected ? "h3" : NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP,
  0,
  cf_ngtcp2_destroy,
  cf_ngtcp2_connect,
  Curl_cf_ngtcp2_cmn_shutdown,
  cf_ngtcp2_adjust_pollset,
  Curl_cf_def_data_pending,
  cf_ngtcp2_send,
  cf_ngtcp2_recv,
  cf_ngtcp2_cntrl,
  Curl_cf_ngtcp2_cmn_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_ngtcp2_query,
};

CURLcode Curl_cf_ngtcp2_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct Curl_peer *origin,
                               struct Curl_peer *peer,
                               struct connectdata *conn,
                               struct Curl_sockaddr_ex *addr)
{
  struct cf_ngtcp2_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  result = Curl_cf_ngtcp2_ctx_init(ctx, origin, peer,
                                   &conn->ssl_config, init_ngh3_conn);
  if(!result)
    result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);
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
    else if(ctx) {
      Curl_cf_ngtcp2_ctx_cleanup(ctx);
      curlx_free(ctx);
    }
  }
  return result;
}

CURLcode Curl_cf_ngtcp2_insert_after(struct Curl_cfilter *cf_at,
                                     struct Curl_peer *origin,
                                     struct Curl_peer *peer)
{
  struct cf_ngtcp2_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  result = Curl_cf_ngtcp2_ctx_init(ctx, origin, peer,
                                   &cf_at->conn->ssl_config, init_ngh3_conn);
  if(!result)
    result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);
  if(result)
    goto out;
  Curl_conn_cf_insert_after(cf_at, cf);
out:
  if(result) {
    curlx_safefree(cf);
    if(ctx) {
      Curl_cf_ngtcp2_ctx_cleanup(ctx);
      curlx_free(ctx);
    }
  }
  return result;
}

#endif
