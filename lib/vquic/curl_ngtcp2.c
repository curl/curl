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

#if defined(USE_NGTCP2) && defined(USE_NGHTTP3)
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#ifdef USE_OPENSSL
#include <openssl/err.h>
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif
#include "vtls/openssl.h"
#elif defined(USE_GNUTLS)
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include "vtls/gtls.h"
#elif defined(USE_WOLFSSL)
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include "vtls/wolfssl.h"
#endif

#include "urldata.h"
#include "hash.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "multiif.h"
#include "strcase.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "strerror.h"
#include "dynbuf.h"
#include "http1.h"
#include "select.h"
#include "inet_pton.h"
#include "transfer.h"
#include "vquic.h"
#include "vquic_int.h"
#include "vquic-tls.h"
#include "vtls/keylog.h"
#include "vtls/vtls.h"
#include "curl_ngtcp2.h"

#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_HANDSHAKE_TIMEOUT (10*NGTCP2_SECONDS)

/* A stream window is the maximum amount we need to buffer for
 * each active transfer. We use HTTP/3 flow control and only ACK
 * when we take things out of the buffer.
 * Chunk size is large enough to take a full DATA frame */
#define H3_STREAM_WINDOW_SIZE (128 * 1024)
#define H3_STREAM_CHUNK_SIZE   (16 * 1024)
/* The pool keeps spares around and half of a full stream windows
 * seems good. More does not seem to improve performance.
 * The benefit of the pool is that stream buffer to not keep
 * spares. Memory consumption goes down when streams run empty,
 * have a large upload done, etc. */
#define H3_STREAM_POOL_SPARES \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE ) / 2
/* Receive and Send max number of chunks just follows from the
 * chunk size and window size */
#define H3_STREAM_RECV_CHUNKS \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)
#define H3_STREAM_SEND_CHUNKS \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)


/*
 * Store ngtcp2 version info in this buffer.
 */
void Curl_ngtcp2_ver(char *p, size_t len)
{
  const ngtcp2_info *ng2 = ngtcp2_version(0);
  const nghttp3_info *ht3 = nghttp3_version(0);
  (void)msnprintf(p, len, "ngtcp2/%s nghttp3/%s",
                  ng2->version_str, ht3->version_str);
}

struct cf_ngtcp2_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
  ngtcp2_path connected_path;
  ngtcp2_conn *qconn;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  uint32_t version;
  ngtcp2_settings settings;
  ngtcp2_transport_params transport_params;
  ngtcp2_ccerr last_error;
  ngtcp2_crypto_conn_ref conn_ref;
  struct cf_call_data call_data;
  nghttp3_conn *h3conn;
  nghttp3_settings h3settings;
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct bufc_pool stream_bufcp;     /* chunk pool for streams */
  struct dynbuf scratch;             /* temp buffer for header construction */
  struct Curl_hash streams;          /* hash `data->mid` to `h3_stream_ctx` */
  size_t max_stream_window;          /* max flow window for one stream */
  uint64_t max_idle_ms;              /* max idle time for QUIC connection */
  uint64_t used_bidi_streams;        /* bidi streams we have opened */
  uint64_t max_bidi_streams;         /* max bidi streams we can open */
  int qlogfd;
  BIT(initialized);
  BIT(shutdown_started);             /* queued shutdown packets */
};

/* How to access `call_data` from a cf_ngtcp2 filter */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_ngtcp2_ctx *)(cf)->ctx)->call_data

static void h3_stream_hash_free(void *stream);

static void cf_ngtcp2_ctx_init(struct cf_ngtcp2_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  ctx->qlogfd = -1;
  ctx->version = NGTCP2_PROTO_VER_MAX;
  ctx->max_stream_window = H3_STREAM_WINDOW_SIZE;
  ctx->max_idle_ms = CURL_QUIC_MAX_IDLE_MS;
  Curl_bufcp_init(&ctx->stream_bufcp, H3_STREAM_CHUNK_SIZE,
                  H3_STREAM_POOL_SPARES);
  Curl_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  Curl_hash_offt_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->initialized = TRUE;
}

static void cf_ngtcp2_ctx_free(struct cf_ngtcp2_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_bufcp_free(&ctx->stream_bufcp);
    Curl_dyn_free(&ctx->scratch);
    Curl_hash_clean(&ctx->streams);
    Curl_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
  }
  free(ctx);
}

struct pkt_io_ctx;
static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct pkt_io_ctx *pktx);
static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct pkt_io_ctx *pktx);

/**
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  curl_int64_t id; /* HTTP/3 protocol identifier */
  struct bufq sendbuf;   /* h3 request body */
  struct h1_req_parser h1; /* h1 request parsing */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  curl_uint64_t error3; /* HTTP/3 stream error code */
  curl_off_t upload_left; /* number of request bytes left to upload */
  int status_code; /* HTTP status code */
  CURLcode xfer_result; /* result from xfer_resp_write(_hd) */
  bool resp_hds_complete; /* we have a complete, final response */
  bool closed; /* TRUE on stream close */
  bool reset;  /* TRUE on stream reset */
  bool send_closed; /* stream is local closed */
  BIT(quic_flow_blocked); /* stream is blocked by QUIC flow control */
};

#define H3_STREAM_CTX(ctx,data)   ((struct h3_stream_ctx *)(\
            data? Curl_hash_offt_get(&(ctx)->streams, (data)->mid) : NULL))
#define H3_STREAM_CTX_ID(ctx,id)  ((struct h3_stream_ctx *)(\
            Curl_hash_offt_get(&(ctx)->streams, (id))))

static void h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
  Curl_bufq_free(&stream->sendbuf);
  Curl_h1_req_parse_free(&stream->h1);
  free(stream);
}

static void h3_stream_hash_free(void *stream)
{
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct h3_stream_ctx *)stream);
}

static CURLcode h3_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(!data)
    return CURLE_FAILED_INIT;

  if(stream)
    return CURLE_OK;

  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  /* on send, we control how much we put into the buffer */
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  stream->sendbuf_len_in_flight = 0;
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_hash_offt_set(&ctx->streams, data->mid, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void cf_ngtcp2_stream_close(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_stream_ctx *stream)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  DEBUGASSERT(data);
  DEBUGASSERT(stream);
  if(!stream->closed && ctx->qconn && ctx->h3conn) {
    CURLcode result;

    nghttp3_conn_set_stream_user_data(ctx->h3conn, stream->id, NULL);
    ngtcp2_conn_set_stream_user_data(ctx->qconn, stream->id, NULL);
    stream->closed = TRUE;
    (void)ngtcp2_conn_shutdown_stream(ctx->qconn, 0, stream->id,
                                      NGHTTP3_H3_REQUEST_CANCELLED);
    result = cf_progress_egress(cf, data, NULL);
    if(result)
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cancel stream -> %d",
                  stream->id, result);
  }
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  if(stream) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] easy handle is done",
                stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    Curl_hash_offt_remove(&ctx->streams, data->mid);
  }
}

static struct Curl_easy *get_stream_easy(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         int64_t stream_id,
                                         struct h3_stream_ctx **pstream)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream;

  (void)cf;
  stream = H3_STREAM_CTX(ctx, data);
  if(stream && stream->id == stream_id) {
    *pstream = stream;
    return data;
  }
  else {
    struct Curl_llist_node *e;
    DEBUGASSERT(data->multi);
    for(e = Curl_llist_head(&data->multi->process); e; e = Curl_node_next(e)) {
      struct Curl_easy *sdata = Curl_node_elem(e);
      if(sdata->conn != data->conn)
        continue;
      stream = H3_STREAM_CTX(ctx, sdata);
      if(stream && stream->id == stream_id) {
        *pstream = stream;
        return sdata;
      }
    }
  }
  *pstream = NULL;
  return NULL;
}

static void h3_drain_stream(struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  unsigned char bits;

  (void)cf;
  bits = CURL_CSELECT_IN;
  if(stream && stream->upload_left && !stream->send_closed)
    bits |= CURL_CSELECT_OUT;
  if(data->state.select_bits != bits) {
    data->state.select_bits = bits;
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
}

/* ngtcp2 default congestion controller does not perform pacing. Limit
   the maximum packet burst to MAX_PKT_BURST packets. */
#define MAX_PKT_BURST 10

struct pkt_io_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  ngtcp2_tstamp ts;
  ngtcp2_path_storage ps;
};

static void pktx_update_time(struct pkt_io_ctx *pktx,
                             struct Curl_cfilter *cf)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  vquic_ctx_update_time(&ctx->q);
  pktx->ts = (ngtcp2_tstamp)ctx->q.last_op.tv_sec * NGTCP2_SECONDS +
             (ngtcp2_tstamp)ctx->q.last_op.tv_usec * NGTCP2_MICROSECONDS;
}

static void pktx_init(struct pkt_io_ctx *pktx,
                      struct Curl_cfilter *cf,
                      struct Curl_easy *data)
{
  pktx->cf = cf;
  pktx->data = data;
  ngtcp2_path_storage_zero(&pktx->ps);
  pktx_update_time(pktx, cf);
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                   uint64_t datalen, void *user_data,
                                   void *stream_user_data);

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  struct Curl_cfilter *cf = conn_ref->user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  return ctx->qconn;
}

#ifdef DEBUG_NGTCP2
static void quic_printf(void *user_data, const char *fmt, ...)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  (void)ctx;  /* TODO: need an easy handle to infof() message */
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
}
#endif

static void qlog_callback(void *user_data, uint32_t flags,
                          const void *data, size_t datalen)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  (void)flags;
  if(ctx->qlogfd != -1) {
    ssize_t rc = write(ctx->qlogfd, data, datalen);
    if(rc == -1) {
      /* on write error, stop further write attempts */
      close(ctx->qlogfd);
      ctx->qlogfd = -1;
    }
  }

}

static void quic_settings(struct cf_ngtcp2_ctx *ctx,
                          struct Curl_easy *data,
                          struct pkt_io_ctx *pktx)
{
  ngtcp2_settings *s = &ctx->settings;
  ngtcp2_transport_params *t = &ctx->transport_params;

  ngtcp2_settings_default(s);
  ngtcp2_transport_params_default(t);
#ifdef DEBUG_NGTCP2
  s->log_printf = quic_printf;
#else
  s->log_printf = NULL;
#endif

  (void)data;
  s->initial_ts = pktx->ts;
  s->handshake_timeout = QUIC_HANDSHAKE_TIMEOUT;
  s->max_window = 100 * ctx->max_stream_window;
  s->max_stream_window = 10 * ctx->max_stream_window;

  t->initial_max_data = 10 * ctx->max_stream_window;
  t->initial_max_stream_data_bidi_local = ctx->max_stream_window;
  t->initial_max_stream_data_bidi_remote = ctx->max_stream_window;
  t->initial_max_stream_data_uni = ctx->max_stream_window;
  t->initial_max_streams_bidi = QUIC_MAX_STREAMS;
  t->initial_max_streams_uni = QUIC_MAX_STREAMS;
  t->max_idle_timeout = (ctx->max_idle_ms * NGTCP2_MILLISECONDS);
  if(ctx->qlogfd != -1) {
    s->qlog_write = qlog_callback;
  }
}

static CURLcode init_ngh3_conn(struct Curl_cfilter *cf);

static int cb_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  (void)user_data;
  (void)tconn;
  return 0;
}

static void cf_ngtcp2_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

static bool cf_ngtcp2_err_is_fatal(int code)
{
  return (NGTCP2_ERR_FATAL >= code) ||
         (NGTCP2_ERR_DROP_CONN == code) ||
         (NGTCP2_ERR_IDLE_CLOSE == code);
}

static void cf_ngtcp2_err_set(struct Curl_cfilter *cf,
                              struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    if(NGTCP2_ERR_CRYPTO == code) {
      ngtcp2_ccerr_set_tls_alert(&ctx->last_error,
                                 ngtcp2_conn_get_tls_alert(ctx->qconn),
                                 NULL, 0);
    }
    else {
      ngtcp2_ccerr_set_liberr(&ctx->last_error, code, NULL, 0);
    }
  }
  if(cf_ngtcp2_err_is_fatal(code))
    cf_ngtcp2_conn_close(cf, data);
}

static bool cf_ngtcp2_h3_err_is_fatal(int code)
{
  return (NGHTTP3_ERR_FATAL >= code) ||
         (NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM == code);
}

static void cf_ngtcp2_h3_err_set(struct Curl_cfilter *cf,
                                 struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    ngtcp2_ccerr_set_application_error(&ctx->last_error,
      nghttp3_err_infer_quic_app_error_code(code), NULL, 0);
  }
  if(cf_ngtcp2_h3_err_is_fatal(code))
    cf_ngtcp2_conn_close(cf, data);
}

static int cb_recv_stream_data(ngtcp2_conn *tconn, uint32_t flags,
                               int64_t sid, uint64_t offset,
                               const uint8_t *buf, size_t buflen,
                               void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  nghttp3_ssize nconsumed;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  struct Curl_easy *data = stream_user_data;
  (void)offset;
  (void)data;

  nconsumed =
    nghttp3_conn_read_stream(ctx->h3conn, stream_id, buf, buflen, fin);
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(data)
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read_stream(len=%zu) -> %zd",
                stream_id, buflen, nconsumed);
  if(nconsumed < 0) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX_ID(ctx, stream_id);
    if(data && stream) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] error on known stream, "
                  "reset=%d, closed=%d",
                  stream_id, stream->reset, stream->closed);
    }
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* number of bytes inside buflen which consists of framing overhead
   * including QPACK HEADERS. In other words, it does not consume payload of
   * DATA frame. */
  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, (uint64_t)nconsumed);
  ngtcp2_conn_extend_max_offset(tconn, (uint64_t)nconsumed);

  return 0;
}

static int
cb_acked_stream_data_offset(ngtcp2_conn *tconn, int64_t stream_id,
                            uint64_t offset, uint64_t datalen, void *user_data,
                            void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rv;
  (void)stream_id;
  (void)tconn;
  (void)offset;
  (void)datalen;
  (void)stream_user_data;

  rv = nghttp3_conn_add_ack_offset(ctx->h3conn, stream_id, datalen);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_close(ngtcp2_conn *tconn, uint32_t flags,
                           int64_t sid, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
  int rv;

  (void)tconn;
  /* stream is closed... */
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(!data)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if(!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  rv = nghttp3_conn_close_stream(ctx->h3conn, stream_id, app_error_code);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] quic close(app_error=%"
              FMT_PRIu64 ") -> %d", stream_id, (curl_uint64_t)app_error_code,
              rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    cf_ngtcp2_h3_err_set(cf, data, rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_reset(ngtcp2_conn *tconn, int64_t sid,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;
  (void)data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_stop_sending(ngtcp2_conn *tconn, int64_t stream_id,
                                  uint64_t app_error_code, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rv;
  (void)tconn;
  (void)app_error_code;
  (void)stream_user_data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_extend_max_local_streams_bidi(ngtcp2_conn *tconn,
                                            uint64_t max_streams,
                                            void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)tconn;
  ctx->max_bidi_streams = max_streams;
  if(data)
    CURL_TRC_CF(data, cf, "max bidi streams now %" FMT_PRIu64
                ", used %" FMT_PRIu64, (curl_uint64_t)ctx->max_bidi_streams,
                (curl_uint64_t)ctx->used_bidi_streams);
  return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *tconn, int64_t sid,
                                     uint64_t max_data, void *user_data,
                                     void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  struct Curl_easy *s_data;
  struct h3_stream_ctx *stream;
  int rv;
  (void)tconn;
  (void)max_data;
  (void)stream_user_data;

  rv = nghttp3_conn_unblock_stream(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  s_data = get_stream_easy(cf, data, stream_id, &stream);
  if(s_data && stream && stream->quic_flow_blocked) {
    CURL_TRC_CF(s_data, cf, "[%" FMT_PRId64 "] unblock quic flow", stream_id);
    stream->quic_flow_blocked = FALSE;
    h3_drain_stream(cf, s_data);
  }
  return 0;
}

static void cb_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
  CURLcode result;
  (void)rand_ctx;

  result = Curl_rand(NULL, dest, destlen);
  if(result) {
    /* cb_rand is only used for non-cryptographic context. If Curl_rand
       failed, just fill 0 and call it *random*. */
    memset(dest, 0, destlen);
  }
}

static int cb_get_new_connection_id(ngtcp2_conn *tconn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
  CURLcode result;
  (void)tconn;
  (void)user_data;

  result = Curl_rand(NULL, cid->data, cidlen);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;

  result = Curl_rand(NULL, token, NGTCP2_STATELESS_RESET_TOKENLEN);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

static int cb_recv_rx_key(ngtcp2_conn *tconn, ngtcp2_encryption_level level,
                          void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  (void)tconn;

  if(level != NGTCP2_ENCRYPTION_LEVEL_1RTT) {
    return 0;
  }

  if(init_ngh3_conn(cf) != CURLE_OK) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(push)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

static ngtcp2_callbacks ng_callbacks = {
  ngtcp2_crypto_client_initial_cb,
  NULL, /* recv_client_initial */
  ngtcp2_crypto_recv_crypto_data_cb,
  cb_handshake_completed,
  NULL, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_recv_stream_data,
  cb_acked_stream_data_offset,
  NULL, /* stream_open */
  cb_stream_close,
  NULL, /* recv_stateless_reset */
  ngtcp2_crypto_recv_retry_cb,
  cb_extend_max_local_streams_bidi,
  NULL, /* extend_max_local_streams_uni */
  cb_rand,
  cb_get_new_connection_id,
  NULL, /* remove_connection_id */
  ngtcp2_crypto_update_key_cb, /* update_key */
  NULL, /* path_validation */
  NULL, /* select_preferred_addr */
  cb_stream_reset,
  NULL, /* extend_max_remote_streams_bidi */
  NULL, /* extend_max_remote_streams_uni */
  cb_extend_max_stream_data,
  NULL, /* dcid_status */
  NULL, /* handshake_confirmed */
  NULL, /* recv_new_token */
  ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  NULL, /* recv_datagram */
  NULL, /* ack_datagram */
  NULL, /* lost_datagram */
  ngtcp2_crypto_get_path_challenge_data_cb,
  cb_stream_stop_sending,
  NULL, /* version_negotiation */
  cb_recv_rx_key,
  NULL, /* recv_tx_key */
  NULL, /* early_data_rejected */
};

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(pop)
#endif

/**
 * Connection maintenance like timeouts on packet ACKs etc. are done by us, not
 * the OS like for TCP. POLL events on the socket therefore are not
 * sufficient.
 * ngtcp2 tells us when it wants to be invoked again. We handle that via
 * the `Curl_expire()` mechanisms.
 */
static CURLcode check_and_set_expiry(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct pkt_io_ctx local_pktx;
  ngtcp2_tstamp expiry;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    pktx_update_time(pktx, cf);
  }

  expiry = ngtcp2_conn_get_expiry(ctx->qconn);
  if(expiry != UINT64_MAX) {
    if(expiry <= pktx->ts) {
      CURLcode result;
      int rv = ngtcp2_conn_handle_expiry(ctx->qconn, pktx->ts);
      if(rv) {
        failf(data, "ngtcp2_conn_handle_expiry returned error: %s",
              ngtcp2_strerror(rv));
        cf_ngtcp2_err_set(cf, data, rv);
        return CURLE_SEND_ERROR;
      }
      result = cf_progress_ingress(cf, data, pktx);
      if(result)
        return result;
      result = cf_progress_egress(cf, data, pktx);
      if(result)
        return result;
      /* ask again, things might have changed */
      expiry = ngtcp2_conn_get_expiry(ctx->qconn);
    }

    if(expiry > pktx->ts) {
      ngtcp2_duration timeout = expiry - pktx->ts;
      if(timeout % NGTCP2_MILLISECONDS) {
        timeout += NGTCP2_MILLISECONDS;
      }
      Curl_expire(data, (timediff_t)(timeout / NGTCP2_MILLISECONDS),
                  EXPIRE_QUIC);
    }
  }
  return CURLE_OK;
}

static void cf_ngtcp2_adjust_pollset(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  bool want_recv, want_send;

  if(!ctx->qconn)
    return;

  Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
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

    Curl_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;

  /* we might be called by nghttp3 after we already cleaned up */
  if(!stream)
    return 0;

  stream->closed = TRUE;
  stream->error3 = (curl_uint64_t)app_error_code;
  if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] RESET: error %" FMT_PRIu64,
                stream->id, stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] CLOSED", stream->id);
  }
  h3_drain_stream(cf, data);
  return 0;
}

static void h3_xfer_write_resp_hd(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream,
                                  const char *buf, size_t blen, bool eos)
{

  /* If we already encountered an error, skip further writes */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp_hd(data, buf, blen, eos);
    if(stream->xfer_result)
      CURL_TRC_CF(data, cf, "[%"FMT_PRId64"] error %d writing %zu "
                  "bytes of headers", stream->id, stream->xfer_result, blen);
  }
}

static void h3_xfer_write_resp(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h3_stream_ctx *stream,
                               const char *buf, size_t blen, bool eos)
{

  /* If we already encountered an error, skip further writes */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp(data, buf, blen, eos);
    /* If the transfer write is errored, we do not want any more data */
    if(stream->xfer_result) {
      CURL_TRC_CF(data, cf, "[%"FMT_PRId64"] error %d writing %zu bytes "
                  "of data", stream->id, stream->xfer_result, blen);
    }
  }
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t blen,
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

  h3_xfer_write_resp(cf, data, stream, (char *)buf, blen, FALSE);
  if(blen) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] ACK %zu bytes of DATA",
                stream->id, blen);
    ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream->id, blen);
    ngtcp2_conn_extend_max_offset(ctx->qconn, blen);
  }
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] DATA len=%zu", stream->id, blen);
  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream3_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  (void)conn;
  (void)stream_user_data;

  /* nghttp3 has consumed bytes on the QUIC stream and we need to
   * tell the QUIC connection to increase its flow control */
  ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream3_id, consumed);
  ngtcp2_conn_extend_max_offset(ctx->qconn, consumed);
  return 0;
}

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t sid,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)cf;

  if(!stream)
    return 0;
  /* add a CRLF only if we have received some headers */
  h3_xfer_write_resp_hd(cf, data, stream, STRCONST("\r\n"), stream->closed);

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] end_headers, status=%d",
              stream_id, stream->status_code);
  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }
  h3_drain_stream(cf, data);
  return 0;
}

static int cb_h3_recv_header(nghttp3_conn *conn, int64_t sid,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
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
      return -1;
    Curl_dyn_reset(&ctx->scratch);
    result = Curl_dyn_addn(&ctx->scratch, STRCONST("HTTP/3 "));
    if(!result)
      result = Curl_dyn_addn(&ctx->scratch,
                             (const char *)h3val.base, h3val.len);
    if(!result)
      result = Curl_dyn_addn(&ctx->scratch, STRCONST(" \r\n"));
    if(!result)
      h3_xfer_write_resp_hd(cf, data, stream, Curl_dyn_ptr(&ctx->scratch),
                            Curl_dyn_len(&ctx->scratch), FALSE);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] status: %s",
                stream_id, Curl_dyn_ptr(&ctx->scratch));
    if(result) {
      return -1;
    }
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] header: %.*s: %.*s",
                stream_id, (int)h3name.len, h3name.base,
                (int)h3val.len, h3val.base);
    Curl_dyn_reset(&ctx->scratch);
    result = Curl_dyn_addn(&ctx->scratch,
                           (const char *)h3name.base, h3name.len);
    if(!result)
      result = Curl_dyn_addn(&ctx->scratch, STRCONST(": "));
    if(!result)
      result = Curl_dyn_addn(&ctx->scratch,
                             (const char *)h3val.base, h3val.len);
    if(!result)
      result = Curl_dyn_addn(&ctx->scratch, STRCONST("\r\n"));
    if(!result)
      h3_xfer_write_resp_hd(cf, data, stream, Curl_dyn_ptr(&ctx->scratch),
                            Curl_dyn_len(&ctx->scratch), FALSE);
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

static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)conn;
  (void)data;

  rv = ngtcp2_conn_shutdown_stream_write(ctx->qconn, 0, stream_id,
                                         app_error_code);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
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
  NULL /* recv_settings */
};

static CURLcode init_ngh3_conn(struct Curl_cfilter *cf)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result;
  int rc;
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;

  if(ngtcp2_conn_get_streams_uni_left(ctx->qconn) < 3) {
    return CURLE_QUIC_CONNECT_ERROR;
  }

  nghttp3_settings_default(&ctx->h3settings);

  rc = nghttp3_conn_client_new(&ctx->h3conn,
                               &ngh3_callbacks,
                               &ctx->h3settings,
                               nghttp3_mem_default(),
                               cf);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &ctrl_stream_id, NULL);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }

  rc = nghttp3_conn_bind_control_stream(ctx->h3conn, ctrl_stream_id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_enc_stream_id, NULL);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_dec_stream_id, NULL);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }

  rc = nghttp3_conn_bind_qpack_streams(ctx->h3conn, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }

  return CURLE_OK;
fail:

  return result;
}

static ssize_t recv_closed_stream(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream,
                                  CURLcode *err)
{
  ssize_t nread = -1;

  (void)cf;
  if(stream->reset) {
    failf(data, "HTTP/3 stream %" FMT_PRId64 " reset by server", stream->id);
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    goto out;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    *err = CURLE_HTTP3;
    goto out;
  }
  *err = CURLE_OK;
  nread = 0;

out:
  return nread;
}

/* incoming data frames on the h3 stream */
static ssize_t cf_ngtcp2_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t blen, CURLcode *err)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nread = -1;
  struct cf_call_data save;
  struct pkt_io_ctx pktx;

  (void)ctx;
  (void)buf;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  *err = CURLE_OK;

  pktx_init(&pktx, cf, data);

  if(!stream || ctx->shutdown_started) {
    *err = CURLE_RECV_ERROR;
    goto out;
  }

  if(cf_progress_ingress(cf, data, &pktx)) {
    *err = CURLE_RECV_ERROR;
    nread = -1;
    goto out;
  }

  if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] xfer write failed", stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    *err = stream->xfer_result;
    nread = -1;
    goto out;
  }
  else if(stream->closed) {
    nread = recv_closed_stream(cf, data, stream, err);
    goto out;
  }
  *err = CURLE_AGAIN;
  nread = -1;

out:
  if(cf_progress_egress(cf, data, &pktx)) {
    *err = CURLE_SEND_ERROR;
    nread = -1;
  }
  else {
    CURLcode result2 = check_and_set_expiry(cf, data, &pktx);
    if(result2) {
      *err = result2;
      nread = -1;
    }
  }
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_recv(blen=%zu) -> %zd, %d",
              stream ? stream->id : -1, blen, nread, *err);
  CF_DATA_RESTORE(cf, save);
  return nread;
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

static nghttp3_ssize
cb_h3_read_req_body(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags, void *user_data,
                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nwritten = 0;
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
                            (const unsigned char **)&vec[nvecs].base,
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
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> AGAIN",
                stream->id);
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> "
              "%d vecs%s with %zu (buffered=%zu, left=%" FMT_OFF_T ")",
              stream->id, (int)nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf),
              stream->upload_left);
  return (nghttp3_ssize)nvecs;
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static ssize_t h3_stream_open(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const void *buf, size_t len,
                              CURLcode *err)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
  int64_t sid;
  struct dynhds h2_headers;
  size_t nheader;
  nghttp3_nv *nva = NULL;
  int rc = 0;
  unsigned int i;
  ssize_t nwritten = -1;
  nghttp3_data_reader reader;
  nghttp3_data_reader *preader = NULL;

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  *err = h3_data_setup(cf, data);
  if(*err)
    goto out;
  stream = H3_STREAM_CTX(ctx, data);
  DEBUGASSERT(stream);
  if(!stream) {
    *err = CURLE_FAILED_INIT;
    goto out;
  }

  nwritten = Curl_h1_req_parse_read(&stream->h1, buf, len, NULL, 0, err);
  if(nwritten < 0)
    goto out;
  if(!stream->h1.done) {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  *err = Curl_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if(*err) {
    nwritten = -1;
    goto out;
  }
  /* no longer needed */
  Curl_h1_req_parse_free(&stream->h1);

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(nghttp3_nv) * nheader);
  if(!nva) {
    *err = CURLE_OUT_OF_MEMORY;
    nwritten = -1;
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
    failf(data, "can get bidi streams");
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }
  stream->id = (curl_int64_t)sid;
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
    /* there is not request body */
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
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send, "
                  "connection is closing", stream->id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send -> "
                  "%d (%s)", stream->id, rc, nghttp3_strerror(rc));
      break;
    }
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" FMT_PRId64 "] OPENED stream for %s",
          stream->id, data->state.url);
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" FMT_PRId64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].namelen, nva[i].name,
            (int)nva[i].valuelen, nva[i].value);
    }
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  return nwritten;
}

static ssize_t cf_ngtcp2_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const void *buf, size_t len, bool eos,
                              CURLcode *err)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t sent = 0;
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  pktx_init(&pktx, cf, data);
  *err = CURLE_OK;

  (void)eos; /* TODO: use for stream EOF and block handling */
  result = cf_progress_ingress(cf, data, &pktx);
  if(result) {
    *err = result;
    sent = -1;
  }

  if(!stream || stream->id < 0) {
    if(ctx->shutdown_started) {
      CURL_TRC_CF(data, cf, "cannot open stream on closed connection");
      *err = CURLE_SEND_ERROR;
      sent = -1;
      goto out;
    }
    sent = h3_stream_open(cf, data, buf, len, err);
    if(sent < 0) {
      CURL_TRC_CF(data, cf, "failed to open stream -> %d", *err);
      goto out;
    }
    stream = H3_STREAM_CTX(ctx, data);
  }
  else if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] xfer write failed", stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    *err = stream->xfer_result;
    sent = -1;
    goto out;
  }
  else if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] discarding data"
                  "on closed stream with response", stream->id);
      *err = CURLE_OK;
      sent = (ssize_t)len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send_body(len=%zu) "
                "-> stream closed", stream->id, len);
    *err = CURLE_HTTP3;
    sent = -1;
    goto out;
  }
  else if(ctx->shutdown_started) {
    CURL_TRC_CF(data, cf, "cannot send on closed connection");
    *err = CURLE_SEND_ERROR;
    sent = -1;
    goto out;
  }
  else {
    sent = Curl_bufq_write(&stream->sendbuf, buf, len, err);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send, add to "
                "sendbuf(len=%zu) -> %zd, %d",
                stream->id, len, sent, *err);
    if(sent < 0) {
      goto out;
    }

    (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
  }

  result = cf_progress_egress(cf, data, &pktx);
  if(result) {
    *err = result;
    sent = -1;
  }

out:
  result = check_and_set_expiry(cf, data, &pktx);
  if(result) {
    *err = result;
    sent = -1;
  }
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send(len=%zu) -> %zd, %d",
              stream ? stream->id : -1, len, sent, *err);
  CF_DATA_RESTORE(cf, save);
  return sent;
}

static CURLcode qng_verify_peer(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  cf->conn->httpversion = 30;

  return Curl_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}

static CURLcode recv_pkt(const unsigned char *pkt, size_t pktlen,
                         struct sockaddr_storage *remote_addr,
                         socklen_t remote_addrlen, int ecn,
                         void *userp)
{
  struct pkt_io_ctx *pktx = userp;
  struct cf_ngtcp2_ctx *ctx = pktx->cf->ctx;
  ngtcp2_pkt_info pi;
  ngtcp2_path path;
  int rv;

  ngtcp2_addr_init(&path.local, (struct sockaddr *)&ctx->q.local_addr,
                   (socklen_t)ctx->q.local_addrlen);
  ngtcp2_addr_init(&path.remote, (struct sockaddr *)remote_addr,
                   remote_addrlen);
  pi.ecn = (uint8_t)ecn;

  rv = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi, pkt, pktlen, pktx->ts);
  if(rv) {
    CURL_TRC_CF(pktx->data, pktx->cf, "ingress, read_pkt -> %s (%d)",
                ngtcp2_strerror(rv), rv);
    cf_ngtcp2_err_set(pktx->cf, pktx->data, rv);

    if(rv == NGTCP2_ERR_CRYPTO)
      /* this is a "TLS problem", but a failed certificate verification
         is a common reason for this */
      return CURLE_PEER_FAILED_VERIFICATION;
    return CURLE_RECV_ERROR;
  }

  return CURLE_OK;
}

static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct pkt_io_ctx local_pktx;
  CURLcode result = CURLE_OK;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }

  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    return result;

  return vquic_recv_packets(cf, data, &ctx->q, 1000, recv_pkt, pktx);
}

/**
 * Read a network packet to send from ngtcp2 into `buf`.
 * Return number of bytes written or -1 with *err set.
 */
static ssize_t read_pkt_to_send(void *userp,
                                unsigned char *buf, size_t buflen,
                                CURLcode *err)
{
  struct pkt_io_ctx *x = userp;
  struct cf_ngtcp2_ctx *ctx = x->cf->ctx;
  nghttp3_vec vec[16];
  nghttp3_ssize veccnt;
  ngtcp2_ssize ndatalen;
  uint32_t flags;
  int64_t stream_id;
  int fin;
  ssize_t nwritten, n;
  veccnt = 0;
  stream_id = -1;
  fin = 0;

  /* ngtcp2 may want to put several frames from different streams into
   * this packet. `NGTCP2_WRITE_STREAM_FLAG_MORE` tells it to do so.
   * When `NGTCP2_ERR_WRITE_MORE` is returned, we *need* to make
   * another iteration.
   * When ngtcp2 is happy (because it has no other frame that would fit
   * or it has nothing more to send), it returns the total length
   * of the assembled packet. This may be 0 if there was nothing to send. */
  nwritten = 0;
  *err = CURLE_OK;
  for(;;) {

    if(ctx->h3conn && ngtcp2_conn_get_max_data_left(ctx->qconn)) {
      veccnt = nghttp3_conn_writev_stream(ctx->h3conn, &stream_id, &fin, vec,
                                          sizeof(vec) / sizeof(vec[0]));
      if(veccnt < 0) {
        failf(x->data, "nghttp3_conn_writev_stream returned error: %s",
              nghttp3_strerror((int)veccnt));
        cf_ngtcp2_h3_err_set(x->cf, x->data, (int)veccnt);
        *err = CURLE_SEND_ERROR;
        return -1;
      }
    }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE |
            (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    n = ngtcp2_conn_writev_stream(ctx->qconn, &x->ps.path,
                                  NULL, buf, buflen,
                                  &ndatalen, flags, stream_id,
                                  (const ngtcp2_vec *)vec, veccnt, x->ts);
    if(n == 0) {
      /* nothing to send */
      *err = CURLE_AGAIN;
      nwritten = -1;
      goto out;
    }
    else if(n < 0) {
      switch(n) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
        struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_block_stream(ctx->h3conn, stream_id);
        CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] block quic flow",
                    (curl_int64_t)stream_id);
        DEBUGASSERT(stream);
        if(stream)
          stream->quic_flow_blocked = TRUE;
        n = 0;
        break;
      }
      case NGTCP2_ERR_STREAM_SHUT_WR:
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_shutdown_stream_write(ctx->h3conn, stream_id);
        n = 0;
        break;
      case NGTCP2_ERR_WRITE_MORE:
        /* ngtcp2 wants to send more. update the flow of the stream whose data
         * is in the buffer and continue */
        DEBUGASSERT(ndatalen >= 0);
        n = 0;
        break;
      default:
        DEBUGASSERT(ndatalen == -1);
        failf(x->data, "ngtcp2_conn_writev_stream returned error: %s",
              ngtcp2_strerror((int)n));
        cf_ngtcp2_err_set(x->cf, x->data, (int)n);
        *err = CURLE_SEND_ERROR;
        nwritten = -1;
        goto out;
      }
    }

    if(ndatalen >= 0) {
      /* we add the amount of data bytes to the flow windows */
      int rv = nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, ndatalen);
      if(rv) {
        failf(x->data, "nghttp3_conn_add_write_offset returned error: %s\n",
              nghttp3_strerror(rv));
        return CURLE_SEND_ERROR;
      }
    }

    if(n > 0) {
      /* packet assembled, leave */
      nwritten = n;
      goto out;
    }
  }
out:
  return nwritten;
}

static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  ssize_t nread;
  size_t max_payload_size, path_max_payload_size, max_pktcnt;
  size_t pktcnt = 0;
  size_t gsolen = 0;  /* this disables gso until we have a clue */
  CURLcode curlcode;
  struct pkt_io_ctx local_pktx;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    pktx_update_time(pktx, cf);
    ngtcp2_path_storage_zero(&pktx->ps);
  }

  curlcode = vquic_flush(cf, data, &ctx->q);
  if(curlcode) {
    if(curlcode == CURLE_AGAIN) {
      Curl_expire(data, 1, EXPIRE_QUIC);
      return CURLE_OK;
    }
    return curlcode;
  }

  /* In UDP, there is a maximum theoretical packet paload length and
   * a minimum payload length that is "guaranteed" to work.
   * To detect if this minimum payload can be increased, ngtcp2 sends
   * now and then a packet payload larger than the minimum. It that
   * is ACKed by the peer, both parties know that it works and
   * the subsequent packets can use a larger one.
   * This is called PMTUD (Path Maximum Transmission Unit Discovery).
   * Since a PMTUD might be rejected right on send, we do not want it
   * be followed by other packets of lesser size. Because those would
   * also fail then. So, if we detect a PMTUD while buffering, we flush.
   */
  max_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(ctx->qconn);
  path_max_payload_size =
      ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
  /* maximum number of packets buffered before we flush to the socket */
  max_pktcnt = CURLMIN(MAX_PKT_BURST,
                       ctx->q.sendbuf.chunk_size / max_payload_size);

  for(;;) {
    /* add the next packet to send, if any, to our buffer */
    nread = Curl_bufq_sipn(&ctx->q.sendbuf, max_payload_size,
                           read_pkt_to_send, pktx, &curlcode);
    if(nread < 0) {
      if(curlcode != CURLE_AGAIN)
        return curlcode;
      /* Nothing more to add, flush and leave */
      curlcode = vquic_send(cf, data, &ctx->q, gsolen);
      if(curlcode) {
        if(curlcode == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return curlcode;
      }
      goto out;
    }

    DEBUGASSERT(nread > 0);
    if(pktcnt == 0) {
      /* first packet in buffer. This is either of a known, "good"
       * payload size or it is a PMTUD. We will see. */
      gsolen = (size_t)nread;
    }
    else if((size_t)nread > gsolen ||
            (gsolen > path_max_payload_size && (size_t)nread != gsolen)) {
      /* The just added packet is a PMTUD *or* the one(s) before the
       * just added were PMTUD and the last one is smaller.
       * Flush the buffer before the last add. */
      curlcode = vquic_send_tail_split(cf, data, &ctx->q,
                                       gsolen, nread, nread);
      if(curlcode) {
        if(curlcode == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return curlcode;
      }
      pktcnt = 0;
      continue;
    }

    if(++pktcnt >= max_pktcnt || (size_t)nread < gsolen) {
      /* Reached MAX_PKT_BURST *or*
       * the capacity of our buffer *or*
       * last add was shorter than the previous ones, flush */
      curlcode = vquic_send(cf, data, &ctx->q, gsolen);
      if(curlcode) {
        if(curlcode == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return curlcode;
      }
      /* pktbuf has been completely sent */
      pktcnt = 0;
    }
  }

out:
  return CURLE_OK;
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
static bool cf_ngtcp2_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  (void)cf;
  (void)data;
  return FALSE;
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  /* TODO: there seems right now no API in ngtcp2 to shrink/enlarge
   * the streams windows. As we do in HTTP/2. */
  if(!pause) {
    h3_drain_stream(cf, data);
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
  return CURLE_OK;
}

static CURLcode cf_ngtcp2_data_event(struct Curl_cfilter *cf,
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
  case CF_CTRL_DATA_DETACH:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
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
  case CF_CTRL_DATA_IDLE: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    CURL_TRC_CF(data, cf, "data idle");
    if(stream && !stream->closed) {
      result = check_and_set_expiry(cf, data, NULL);
      if(result)
        CURL_TRC_CF(data, cf, "data idle, check_and_set_expiry -> %d", result);
    }
    break;
  }
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
    close(ctx->qlogfd);
  }
  ctx->qlogfd = -1;
  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
  if(ctx->h3conn)
    nghttp3_conn_del(ctx->h3conn);
  if(ctx->qconn)
    ngtcp2_conn_del(ctx->qconn);
  ctx->call_data = save;
}

static CURLcode cf_ngtcp2_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data, bool *done)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;
  pktx_init(&pktx, cf, data);

  if(!ctx->shutdown_started) {
    char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    ngtcp2_ssize nwritten;

    if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
      result = cf_progress_egress(cf, data, &pktx);
      if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
        CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
        result = CURLE_OK;
        goto out;
      }
      else if(result) {
        CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
        *done = TRUE;
        goto out;
      }
    }

    ctx->shutdown_started = TRUE;
    nwritten = ngtcp2_conn_write_connection_close(
      ctx->qconn, NULL, /* path */
      NULL, /* pkt_info */
      (uint8_t *)buffer, sizeof(buffer),
      &ctx->last_error, pktx.ts);
    CURL_TRC_CF(data, cf, "start shutdown(err_type=%d, err_code=%"
                FMT_PRIu64 ") -> %d", ctx->last_error.type,
                (curl_uint64_t)ctx->last_error.error_code, (int)nwritten);
    if(nwritten > 0) {
      Curl_bufq_write(&ctx->q.sendbuf, (const unsigned char *)buffer,
                      (size_t)nwritten, &result);
      if(result) {
        CURL_TRC_CF(data, cf, "error %d adding shutdown packets to sendbuf, "
                    "aborting shutdown", result);
        goto out;
      }
      ctx->q.no_gso = TRUE;
      ctx->q.gsolen = (size_t)nwritten;
      ctx->q.split_len = 0;
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    CURL_TRC_CF(data, cf, "shutdown, flushing egress");
    result = vquic_flush(cf, data, &ctx->q);
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
      result = CURLE_OK;
      goto out;
    }
    else if(result) {
      CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
      *done = TRUE;
      goto out;
    }
  }

  if(Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* Sent everything off. ngtcp2 seems to have no support for graceful
     * shutdowns. So, we are done. */
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
    result = CURLE_OK;
  }
out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_ngtcp2_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  bool done;
  cf_ngtcp2_shutdown(cf, data, &done);
}

static void cf_ngtcp2_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  if(ctx && ctx->qconn) {
    cf_ngtcp2_conn_close(cf, data);
    cf_ngtcp2_ctx_close(ctx);
    CURL_TRC_CF(data, cf, "close");
  }
  cf->connected = FALSE;
  CF_DATA_RESTORE(cf, save);
}

static void cf_ngtcp2_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  CURL_TRC_CF(data, cf, "destroy");
  if(cf->ctx) {
    cf_ngtcp2_ctx_free(cf->ctx);
    cf->ctx = NULL;
  }
}

#ifdef USE_OPENSSL
/* The "new session" callback must return zero if the session can be removed
 * or non-zero if the session has been put into the session cache.
 */
static int quic_ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid)
{
  struct Curl_cfilter *cf;
  struct cf_ngtcp2_ctx *ctx;
  struct Curl_easy *data;
  ngtcp2_crypto_conn_ref *cref;

  cref = (ngtcp2_crypto_conn_ref *)SSL_get_app_data(ssl);
  cf = cref ? cref->user_data : NULL;
  ctx = cf ? cf->ctx : NULL;
  data = cf ? CF_DATA_CURRENT(cf) : NULL;
  if(cf && data && ctx) {
    Curl_ossl_add_session(cf, data, &ctx->peer, ssl_sessionid);
    return 1;
  }
  return 0;
}
#endif /* USE_OPENSSL */

#ifdef USE_GNUTLS
static int quic_gtls_handshake_cb(gnutls_session_t session, unsigned int htype,
                                  unsigned when, unsigned int incoming,
                                  const gnutls_datum_t *msg)
{
  ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
  struct Curl_cfilter *cf = conn_ref ? conn_ref->user_data : NULL;
  struct cf_ngtcp2_ctx *ctx = cf ? cf->ctx : NULL;

  (void)msg;
  (void)incoming;
  if(when && cf && ctx) { /* after message has been processed */
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    DEBUGASSERT(data);
    if(data) {
      CURL_TRC_CF(data, cf, "handshake: %s message type %d",
                  incoming ? "incoming" : "outgoing", htype);
    }
    switch(htype) {
    case GNUTLS_HANDSHAKE_NEW_SESSION_TICKET: {
      (void)Curl_gtls_update_session_id(cf, data, session, &ctx->peer, "h3");
      break;
    }
    default:
      break;
    }
  }
  return 0;
}
#endif /* USE_GNUTLS */

#ifdef USE_WOLFSSL
static int wssl_quic_new_session_cb(WOLFSSL *ssl, WOLFSSL_SESSION *session)
{
  ngtcp2_crypto_conn_ref *conn_ref = wolfSSL_get_app_data(ssl);
  struct Curl_cfilter *cf = conn_ref ? conn_ref->user_data : NULL;

  DEBUGASSERT(cf != NULL);
  if(cf && session) {
    struct cf_ngtcp2_ctx *ctx = cf->ctx;
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    DEBUGASSERT(data);
    if(data && ctx) {
      (void)wssl_cache_session(cf, data, &ctx->peer, session);
    }
  }
  return 0;
}
#endif /* USE_WOLFSSL */

static CURLcode tls_ctx_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              void *user_data)
{
  struct curl_tls_ctx *ctx = user_data;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

#ifdef USE_OPENSSL
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
  if(ngtcp2_crypto_boringssl_configure_client_context(ctx->ossl.ssl_ctx)
     != 0) {
    failf(data, "ngtcp2_crypto_boringssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#else
  if(ngtcp2_crypto_quictls_configure_client_context(ctx->ossl.ssl_ctx) != 0) {
    failf(data, "ngtcp2_crypto_quictls_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#endif /* !OPENSSL_IS_BORINGSSL && !OPENSSL_IS_AWSLC */
  if(ssl_config->primary.cache_session) {
    /* Enable the session cache because it is a prerequisite for the
     * "new session" callback. Use the "external storage" mode to prevent
     * OpenSSL from creating an internal session cache.
     */
    SSL_CTX_set_session_cache_mode(ctx->ossl.ssl_ctx,
                                   SSL_SESS_CACHE_CLIENT |
                                   SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(ctx->ossl.ssl_ctx, quic_ossl_new_session_cb);
  }

#elif defined(USE_GNUTLS)
  if(ngtcp2_crypto_gnutls_configure_client_session(ctx->gtls.session) != 0) {
    failf(data, "ngtcp2_crypto_gnutls_configure_client_session failed");
    return CURLE_FAILED_INIT;
  }
  if(ssl_config->primary.cache_session) {
    gnutls_handshake_set_hook_function(ctx->gtls.session,
                                       GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_POST,
                                       quic_gtls_handshake_cb);
  }

#elif defined(USE_WOLFSSL)
  if(ngtcp2_crypto_wolfssl_configure_client_context(ctx->wssl.ctx) != 0) {
    failf(data, "ngtcp2_crypto_wolfssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
  if(ssl_config->primary.cache_session) {
    /* Register to get notified when a new session is received */
    wolfSSL_CTX_sess_set_new_cb(ctx->wssl.ctx, wssl_quic_new_session_cb);
  }
#endif
  return CURLE_OK;
}

/*
 * Might be called twice for happy eyeballs.
 */
static CURLcode cf_connect_start(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rc;
  int rv;
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int qfd;

  DEBUGASSERT(ctx->initialized);
  result = Curl_ssl_peer_init(&ctx->peer, cf, TRNSPRT_QUIC);
  if(result)
    return result;

#define H3_ALPN "\x2h3\x5h3-29"
  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               H3_ALPN, sizeof(H3_ALPN) - 1,
                               tls_ctx_setup, &ctx->tls, &ctx->conn_ref);
  if(result)
    return result;

#ifdef USE_OPENSSL
  SSL_set_quic_use_legacy_codepoint(ctx->tls.ossl.ssl, 0);
#endif

  ctx->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  ctx->scid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->scid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  (void)Curl_qlogdir(data, ctx->scid.data, NGTCP2_MAX_CIDLEN, &qfd);
  ctx->qlogfd = qfd; /* -1 if failure above */
  quic_settings(ctx, data, pktx);

  result = vquic_ctx_init(&ctx->q);
  if(result)
    return result;

  Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL);
  if(!sockaddr)
    return CURLE_QUIC_CONNECT_ERROR;
  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                   &ctx->q.local_addrlen);
  if(rv == -1)
    return CURLE_QUIC_CONNECT_ERROR;

  ngtcp2_addr_init(&ctx->connected_path.local,
                   (struct sockaddr *)&ctx->q.local_addr,
                   ctx->q.local_addrlen);
  ngtcp2_addr_init(&ctx->connected_path.remote,
                   &sockaddr->curl_sa_addr, (socklen_t)sockaddr->addrlen);

  rc = ngtcp2_conn_client_new(&ctx->qconn, &ctx->dcid, &ctx->scid,
                              &ctx->connected_path,
                              NGTCP2_PROTO_VER_V1, &ng_callbacks,
                              &ctx->settings, &ctx->transport_params,
                              NULL, cf);
  if(rc)
    return CURLE_QUIC_CONNECT_ERROR;

#ifdef USE_OPENSSL
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.ossl.ssl);
#elif defined(USE_GNUTLS)
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.gtls.session);
#elif defined(USE_WOLFSSL)
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.wssl.handle);
#else
  #error "ngtcp2 TLS backend not defined"
#endif

  ngtcp2_ccerr_default(&ctx->last_error);

  ctx->conn_ref.get_conn = get_conn;
  ctx->conn_ref.user_data = cf;

  return CURLE_OK;
}

static CURLcode cf_ngtcp2_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool blocking, bool *done)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  struct curltime now;
  struct pkt_io_ctx pktx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the UDP filter first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, blocking, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  now = Curl_now();
  pktx_init(&pktx, cf, data);

  CF_DATA_SAVE(save, cf, data);

  if(!ctx->qconn) {
    ctx->started_at = now;
    result = cf_connect_start(cf, data, &pktx);
    if(result)
      goto out;
    result = cf_progress_egress(cf, data, &pktx);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = cf_progress_ingress(cf, data, &pktx);
  if(result)
    goto out;

  result = cf_progress_egress(cf, data, &pktx);
  if(result)
    goto out;

  if(ngtcp2_conn_get_handshake_completed(ctx->qconn)) {
    ctx->handshake_at = now;
    CURL_TRC_CF(data, cf, "handshake complete after %dms",
               (int)Curl_timediff(now, ctx->started_at));
    result = qng_verify_peer(cf, data);
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }

out:
  if(result == CURLE_RECV_ERROR && ctx->qconn &&
     ngtcp2_conn_in_draining_period(ctx->qconn)) {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state. The CONNECT may work in the near future again. Indicate
     * that as a "weird" reply. */
    result = CURLE_WEIRD_SERVER_REPLY;
  }

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result) {
    struct ip_quadruple ip;

    Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
    infof(data, "QUIC connect to %s port %u failed: %s",
          ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
  }
#endif
  if(!result && ctx->qconn) {
    result = check_and_set_expiry(cf, data, &pktx);
  }
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
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
      uint64_t max_streams = CONN_INUSE(cf->conn);
      if(ctx->max_bidi_streams > ctx->used_bidi_streams)
        avail_bidi_streams = ctx->max_bidi_streams - ctx->used_bidi_streams;
      max_streams += avail_bidi_streams;
      *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    }
    else  /* transport params not arrived yet? take our default. */
      *pres1 = (int)Curl_multi_max_concurrent_streams(data->multi);
    CURL_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%zu in use)",
                cf->conn->connection_id, *pres1, CONN_INUSE(cf->conn));
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->q.got_first_byte) {
      timediff_t ms = Curl_timediff(ctx->q.first_byte_at, ctx->started_at);
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
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_ngtcp2_conn_is_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *input_pending)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  bool alive = FALSE;
  const ngtcp2_transport_params *rp;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  *input_pending = FALSE;
  if(!ctx->qconn || ctx->shutdown_started)
    goto out;

  /* Both sides of the QUIC connection announce they max idle times in
   * the transport parameters. Look at the minimum of both and if
   * we exceed this, regard the connection as dead. The other side
   * may have completely purged it and will no longer respond
   * to any packets from us. */
  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(rp) {
    timediff_t idletime;
    uint64_t idle_ms = ctx->max_idle_ms;

    if(rp->max_idle_timeout &&
      (rp->max_idle_timeout / NGTCP2_MILLISECONDS) < idle_ms)
      idle_ms = (rp->max_idle_timeout / NGTCP2_MILLISECONDS);
    idletime = Curl_timediff(Curl_now(), ctx->q.last_io);
    if(idletime > 0 && (uint64_t)idletime > idle_ms)
      goto out;
  }

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    goto out;

  alive = TRUE;
  if(*input_pending) {
    CURLcode result;
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
    result = cf_progress_ingress(cf, data, NULL);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result ? FALSE : TRUE;
  }

out:
  CF_DATA_RESTORE(cf, save);
  return alive;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX,
  0,
  cf_ngtcp2_destroy,
  cf_ngtcp2_connect,
  cf_ngtcp2_close,
  cf_ngtcp2_shutdown,
  Curl_cf_def_get_host,
  cf_ngtcp2_adjust_pollset,
  cf_ngtcp2_data_pending,
  cf_ngtcp2_send,
  cf_ngtcp2_recv,
  cf_ngtcp2_data_event,
  cf_ngtcp2_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_ngtcp2_query,
};

CURLcode Curl_cf_ngtcp2_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct Curl_addrinfo *ai)
{
  struct cf_ngtcp2_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL, *udp_cf = NULL;
  CURLcode result;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_ngtcp2_ctx_init(ctx);

  result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);
  if(result)
    goto out;

  result = Curl_cf_udp_create(&udp_cf, data, conn, ai, TRNSPRT_QUIC);
  if(result)
    goto out;

  cf->conn = conn;
  udp_cf->conn = cf->conn;
  udp_cf->sockindex = cf->sockindex;
  cf->next = udp_cf;

out:
  *pcf = (!result) ? cf : NULL;
  if(result) {
    if(udp_cf)
      Curl_conn_cf_discard_sub(cf, udp_cf, data, TRUE);
    Curl_safefree(cf);
    cf_ngtcp2_ctx_free(ctx);
  }
  return result;
}

bool Curl_conn_is_ngtcp2(const struct Curl_easy *data,
                         const struct connectdata *conn,
                         int sockindex)
{
  struct Curl_cfilter *cf = conn ? conn->cfilter[sockindex] : NULL;

  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_http3)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

#endif
