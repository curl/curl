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

#if !defined(CURL_DISABLE_HTTP) && \
    defined(USE_NGHTTP3) && !defined(CURL_DISABLE_PROXY) && \
    defined(USE_NGTCP2) && defined(USE_OPENSSL)

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#ifdef USE_OPENSSL
#include <openssl/err.h>
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#elif defined(OPENSSL_QUIC_API2)
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif
#include "vtls/openssl.h"
#endif /* USE_OPENSSL */

#include <nghttp3/nghttp3.h>

#include "urldata.h"
#include "hash.h"
#include "sendf.h"
#include "multiif.h"
#include "cfilters.h"
#include "cf-dns.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "curlx/fopen.h"
#include "curlx/dynbuf.h"
#include "dynhds.h"
#include "http_proxy.h"
#include "select.h"
#include "uint-hash.h"
#include "vquic/vquic.h"
#include "vquic/vquic_int.h"
#include "vquic/vquic-tls.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "curl_trc.h"
#include "cf-h3-proxy.h"
#include "url.h"
#include "capsule.h"
#include "rand.h"

/* A stream window is the maximum amount we need to buffer for
 * each active transfer. We use HTTP/3 flow control and only ACK
 * when we take things out of the buffer.
 * Chunk size is large enough to take a full DATA frame */
#define PROXY_H3_STREAM_WINDOW_SIZE (128 * 1024)
#define PROXY_H3_STREAM_CHUNK_SIZE (16 * 1024)

/* The pool keeps spares around and half of a full stream window
 * seems good. More does not seem to improve performance.
 * The benefit of the pool is that stream buffer to not keep
 * spares. Memory consumption goes down when streams run empty,
 * have a large upload done, etc. */
#define PROXY_H3_STREAM_POOL_SPARES \
  ((PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE) / 2)

#define PROXY_H3_STREAM_RECV_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)
#define PROXY_H3_STREAM_SEND_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)

#define PROXY_QUIC_MAX_STREAMS (256*1024)
#define PROXY_QUIC_HANDSHAKE_TIMEOUT (10*NGTCP2_SECONDS)
#define PROXY_QUIC_TUNNEL_INBUF_SIZE (64 * 1024)
#define PROXY_QUIC_INGRESS_PKT_LIMIT 1000

typedef enum
{
  H3_TUNNEL_INIT,     /* init/default/no tunnel state */
  H3_TUNNEL_CONNECT,  /* CONNECT request is being sent */
  H3_TUNNEL_RESPONSE, /* CONNECT response received completely */
  H3_TUNNEL_ESTABLISHED,
  H3_TUNNEL_FAILED
} h3_tunnel_state;

struct h3_proxy_stream_ctx;

struct h3_tunnel_stream
{
  struct http_resp *resp;
  char *authority;
  struct h3_proxy_stream_ctx *stream;
  int64_t stream_id;
  h3_tunnel_state state;
  BIT(has_final_response);
  BIT(closed);
};

static CURLcode h3_tunnel_stream_init(struct Curl_cfilter *cf,
                                   struct h3_tunnel_stream *ts)
{
  const char *hostname;
  uint16_t port;
  bool ipv6_ip;

  ts->state = H3_TUNNEL_INIT;
  ts->stream_id = -1;
  ts->has_final_response = FALSE;

  Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip);

  /* host:port with IPv6 support */
  ts->authority = curl_maprintf("%s%s%s:%u", ipv6_ip ? "[" : "", hostname,
                                ipv6_ip ? "]" : "", (unsigned int)port);
  if(!ts->authority)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static void h3_tunnel_stream_clear(struct h3_tunnel_stream *ts)
{
  Curl_http_resp_free(ts->resp);
  curlx_safefree(ts->authority);
  memset(ts, 0, sizeof(*ts));
  ts->state = H3_TUNNEL_INIT;
}

static void h3_tunnel_go_state(struct Curl_cfilter *cf,
                               struct h3_tunnel_stream *ts,
                               h3_tunnel_state new_state,
                               struct Curl_easy *data,
                               bool udp_tunnel)
{
  (void)cf;
  (void)udp_tunnel;

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
    CURL_TRC_CF(data, cf, "[%" PRId64 "] new tunnel state 'init'",
                ts->stream_id);
    h3_tunnel_stream_clear(ts);
    break;

  case H3_TUNNEL_CONNECT:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] new tunnel state 'connect'",
                ts->stream_id);
    ts->state = H3_TUNNEL_CONNECT;
    break;

  case H3_TUNNEL_RESPONSE:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] new tunnel state 'response'",
                ts->stream_id);
    ts->state = H3_TUNNEL_RESPONSE;
    break;

  case H3_TUNNEL_ESTABLISHED:
    CURL_TRC_CF(data, cf, "[%" PRId64 "] new tunnel state 'established'",
                ts->stream_id);
    infof(data, "CONNECT%s phase completed for HTTP/3 proxy",
          udp_tunnel ? "-UDP" : "");
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    FALLTHROUGH();
  case H3_TUNNEL_FAILED:
    if(new_state == H3_TUNNEL_FAILED)
      CURL_TRC_CF(data, cf, "[%" PRId64 "] new tunnel state 'failed'",
                  ts->stream_id);
    ts->state = new_state;
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it is not accidentally used for the document request
       after we have connected. So let's free and clear it here. */
    curlx_safefree(data->req.proxyuserpwd);
    break;
  }
}

struct cf_ngtcp2_proxy_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
#ifdef OPENSSL_QUIC_API2
  ngtcp2_crypto_ossl_ctx *ossl_ctx;
#endif /* OPENSSL_QUIC_API2 */
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
  struct uint_hash streams;
                            /* hash `data->mid` to `h3_proxy_stream_ctx` */
  uint64_t used_bidi_streams;        /* bidi streams we have opened */
  uint64_t max_bidi_streams;         /* max bidi streams we can open */
  size_t earlydata_max;              /* max amount of early data supported by
                                        server on session reuse */
  size_t earlydata_skip;             /* sending bytes to skip when earlydata
                                        is accepted by peer */
  CURLcode tls_vrfy_result;          /* result of TLS peer verification */
  int qlogfd;
  struct Curl_addrinfo *addr;        /* remote addr */
  unsigned char *tunnel_inbuf;       /* CONNECT-UDP ingress buffer */
  size_t tunnel_inbuf_len;
  BIT(initialized);
  BIT(tls_handshake_complete);       /* TLS handshake is done */
  BIT(use_earlydata);                /* Using 0RTT data */
  BIT(earlydata_accepted);           /* 0RTT was accepted by server */
  BIT(shutdown_started);             /* queued shutdown packets */
};

struct cf_h3_proxy_ctx
{
  struct cf_ngtcp2_proxy_ctx *ngtcp2_ctx;
  struct cf_call_data call_data; /* fallback before backend ctx exists */
  struct bufq inbufq;          /* network receive buffer */
  struct h3_tunnel_stream tunnel; /* our tunnel CONNECT stream */
  BIT(connected);
  BIT(udp_tunnel);
};

/**
 * All about the H3 internals of a stream
 */
struct h3_proxy_stream_ctx
{
  int64_t id;              /* HTTP/3 stream identifier */
  struct bufq sendbuf;          /* h3 request body */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  uint64_t error3;         /* HTTP/3 stream error code */
  curl_off_t upload_left;       /* number of request bytes left to upload */
  curl_off_t tun_data_recvd;    /* number of bytes received over tunnel */
  int status_code;              /* HTTP status code */
  CURLcode xfer_result;         /* result from xfer_resp_write(_hd) */
  BIT(resp_hds_complete);       /* we have a complete, final response */
  BIT(closed);                  /* TRUE on stream close */
  BIT(reset);                   /* TRUE on stream reset */
  BIT(send_closed);             /* stream is local closed */
  BIT(quic_flow_blocked);       /* stream is blocked by QUIC flow control */
};

#define H3_PROXY_STREAM_CTX(ctx, data)                                     \
  ((data) ? Curl_uint32_hash_get(&(ctx)->streams, (data)->mid) : NULL)

#define H3_STREAM_ID(stream) ((stream)->id)

static void h3_proxy_stream_ctx_free(struct h3_proxy_stream_ctx *stream)
{
  Curl_bufq_free(&stream->sendbuf);
  curlx_free(stream);
}

static void h3_proxy_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h3_proxy_stream_ctx_free((struct h3_proxy_stream_ctx *)stream);
}

static void cf_ngtcp2_proxy_ctx_init(struct cf_ngtcp2_proxy_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  ctx->qlogfd = -1;
  ctx->tunnel_inbuf = NULL;
  ctx->tunnel_inbuf_len = 0;
  ctx->version = NGTCP2_PROTO_VER_MAX;
  Curl_bufcp_init(&ctx->stream_bufcp, PROXY_H3_STREAM_CHUNK_SIZE,
                  PROXY_H3_STREAM_POOL_SPARES);
  curlx_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  Curl_uint32_hash_init(&ctx->streams, 63, h3_proxy_stream_hash_free);
  ctx->initialized = TRUE;
}

static void cf_ngtcp2_proxy_ctx_free(struct cf_ngtcp2_proxy_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_vquic_tls_cleanup(&ctx->tls);
    vquic_ctx_free(&ctx->q);
    Curl_bufcp_free(&ctx->stream_bufcp);
    curlx_dyn_free(&ctx->scratch);
    Curl_uint32_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
    curlx_safefree(ctx->tunnel_inbuf);
    ctx->tunnel_inbuf_len = 0;
  }
  curlx_free(ctx);
}

static void cf_ngtcp2_proxy_ctx_close(struct cf_ngtcp2_proxy_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(!ctx->initialized)
    return;
  if(ctx->qlogfd != -1) {
    curlx_close(ctx->qlogfd);
  }
  ctx->qlogfd = -1;
  Curl_vquic_tls_cleanup(&ctx->tls);
  Curl_ssl_peer_cleanup(&ctx->peer);
  vquic_ctx_free(&ctx->q);
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
#endif /* OPENSSL_QUIC_API2 */
  ctx->call_data = save;
}

static void cf_ngtcp2_proxy_setup_keep_alive(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  const ngtcp2_transport_params *rp;
  /* Peer should have sent us its transport parameters. If it
  * announces a positive `max_idle_timeout` it will close the
  * connection when it does not hear from us for that time.
  *
  * Some servers use this as a keep-alive timer at a rather low
  * value. We are doing HTTP/3 here and waiting for the response
  * to a request may take a considerable amount of time. We need
  * to prevent the peer's QUIC stack from closing in this case.
  */
  if(!ctx->qconn)
    return;

  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(!rp || !rp->max_idle_timeout) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no peer idle timeout, unset keep-alive");
  }
  else if(!Curl_uint32_hash_count(&ctx->streams)) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no active streams, unset keep-alive");
  }
  else {
    ngtcp2_duration keep_ns;
    keep_ns = (rp->max_idle_timeout > 1) ? (rp->max_idle_timeout / 2) : 1;
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, keep_ns);
    CURL_TRC_CF(data, cf, "peer idle timeout is %" PRIu64 "ms, "
                "set keep-alive to %" PRIu64 " ms.",
                (uint64_t)(rp->max_idle_timeout / NGTCP2_MILLISECONDS),
                (uint64_t)(keep_ns / NGTCP2_MILLISECONDS));
  }
}

struct proxy_pkt_io_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  ngtcp2_tstamp ts;
  ngtcp2_path_storage ps;
};

static void proxy_pktx_update_time(struct proxy_pkt_io_ctx *pktx,
                                   struct Curl_cfilter *cf)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  const struct curltime *pnow = Curl_pgrs_now(pktx->data);

  vquic_ctx_update_time(&ctx->q, pnow);
  pktx->ts = ((ngtcp2_tstamp)pnow->tv_sec * NGTCP2_SECONDS) +
             ((ngtcp2_tstamp)pnow->tv_usec * NGTCP2_MICROSECONDS);
}

static void proxy_pktx_init(struct proxy_pkt_io_ctx *pktx,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  const struct curltime *pnow = Curl_pgrs_now(data);

  pktx->cf = cf;
  pktx->data = data;
  ngtcp2_path_storage_zero(&pktx->ps);
  vquic_ctx_set_time(&ctx->q, pnow);
  pktx->ts = ((ngtcp2_tstamp)pnow->tv_sec * NGTCP2_SECONDS) +
             ((ngtcp2_tstamp)pnow->tv_usec * NGTCP2_MICROSECONDS);
}

static ngtcp2_conn *proxy_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  struct Curl_cfilter *cf = conn_ref->user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  return ctx->qconn;
}

#ifdef DEBUG_NGTCP2
static void proxy_quic_printf(void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void)user_data;
  va_start(ap, fmt);
  curl_mvfprintf(stderr, fmt, ap);
  va_end(ap);
  curl_mfprintf(stderr, "\n");
}
#endif /* DEBUG_NGTCP2 */

static void proxy_qlog_callback(void *user_data, uint32_t flags,
                          const void *data, size_t datalen)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  (void)flags;
  if(ctx->qlogfd != -1) {
    ssize_t rc = write(ctx->qlogfd, data, datalen);
    if(rc == -1) {
      /* on write error, stop further write attempts */
      curlx_close(ctx->qlogfd);
      ctx->qlogfd = -1;
    }
  }
}

static void quic_settings_proxy(struct cf_ngtcp2_proxy_ctx *ctx,
                                struct Curl_easy *data,
                                struct proxy_pkt_io_ctx *pktx)
{
  ngtcp2_settings *s = &ctx->settings;
  ngtcp2_transport_params *t = &ctx->transport_params;

  ngtcp2_settings_default(s);
  ngtcp2_transport_params_default(t);
#ifdef DEBUG_NGTCP2
  s->log_printf = proxy_quic_printf;
#else
  s->log_printf = NULL;
#endif /* DEBUG_NGTCP2 */

  s->initial_ts = pktx->ts;
  s->handshake_timeout = (data->set.connecttimeout > 0) ?
    data->set.connecttimeout * NGTCP2_MILLISECONDS :
    PROXY_QUIC_HANDSHAKE_TIMEOUT;
  s->max_window = 100 * PROXY_H3_STREAM_WINDOW_SIZE;
  s->max_stream_window = 10 * PROXY_H3_STREAM_WINDOW_SIZE;
  s->no_pmtud = FALSE;
#ifdef NGTCP2_SETTINGS_V3
  /* try ten times the ngtcp2 defaults here for problems with Caddy */
  s->glitch_ratelim_burst = 1000 * 10;
  s->glitch_ratelim_rate = 33 * 10;
#endif /* NGTCP2_SETTINGS_V3 */
  t->initial_max_data = 10 * PROXY_H3_STREAM_WINDOW_SIZE;
  t->initial_max_stream_data_bidi_local = PROXY_H3_STREAM_WINDOW_SIZE;
  t->initial_max_stream_data_bidi_remote = PROXY_H3_STREAM_WINDOW_SIZE;
  t->initial_max_stream_data_uni = PROXY_H3_STREAM_WINDOW_SIZE;
  t->initial_max_streams_bidi = PROXY_QUIC_MAX_STREAMS;
  t->initial_max_streams_uni = PROXY_QUIC_MAX_STREAMS;
  t->max_idle_timeout = 0; /* no idle timeout from our side */
  if(ctx->qlogfd != -1) {
    s->qlog_write = proxy_qlog_callback;
  }
}

static void cf_ngtcp2_proxy_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

static bool cf_ngtcp2_proxy_err_is_fatal(int code)
{
  return (NGTCP2_ERR_FATAL >= code) ||
         (NGTCP2_ERR_DROP_CONN == code) ||
         (NGTCP2_ERR_IDLE_CLOSE == code);
}

static void cf_ngtcp2_proxy_err_set(struct Curl_cfilter *cf,
                              struct Curl_easy *data, int code)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
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
  if(cf_ngtcp2_proxy_err_is_fatal(code))
    cf_ngtcp2_proxy_conn_close(cf, data);
}

static bool cf_ngtcp2_proxy_h3_err_is_fatal(int code)
{
  return (NGHTTP3_ERR_FATAL >= code) ||
         (NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM == code);
}

static void cf_ngtcp2_proxy_h3_err_set(struct Curl_cfilter *cf,
                                 struct Curl_easy *data, int code)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  if(!ctx->last_error.error_code) {
    ngtcp2_ccerr_set_application_error(&ctx->last_error,
      nghttp3_err_infer_quic_app_error_code(code), NULL, 0);
  }
  if(cf_ngtcp2_proxy_h3_err_is_fatal(code))
    cf_ngtcp2_proxy_conn_close(cf, data);
}

/* How to access `call_data` from a cf_h3_proxy filter */
#undef CF_CTX_CALL_DATA
static struct cf_call_data *cf_h3_proxy_call_data(struct Curl_cfilter *cf)
{
  struct cf_h3_proxy_ctx *ctx = cf ? cf->ctx : NULL;
  static struct cf_call_data no_ctx;

  if(!ctx)
    return &no_ctx;
  if(ctx->ngtcp2_ctx)
    return &ctx->ngtcp2_ctx->call_data;
  return &ctx->call_data;
}

#define CF_CTX_CALL_DATA(cf) (*cf_h3_proxy_call_data(cf))

static void cf_h3_proxy_ctx_clear(struct cf_h3_proxy_ctx *ctx)
{
  Curl_bufq_free(&ctx->inbufq);
  h3_tunnel_stream_clear(&ctx->tunnel);
  memset(ctx, 0, sizeof(*ctx));
}

static void cf_h3_proxy_ctx_free(struct cf_h3_proxy_ctx *ctx)
{
  if(ctx) {
    cf_h3_proxy_ctx_clear(ctx);
    curlx_free(ctx);
  }
}

static CURLcode h3_proxy_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream = NULL;

  if(!data)
    return CURLE_FAILED_INIT;

  if(!ctx)
    return CURLE_FAILED_INIT;

  stream = H3_PROXY_STREAM_CTX(ctx, data);
  if(stream)
    return CURLE_OK;

  stream = curlx_calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  /* on send, we control how much we put into the buffer */
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  PROXY_H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  stream->sendbuf_len_in_flight = 0;

  if(!Curl_uint32_hash_set(&ctx->streams, data->mid, stream)) {
    h3_proxy_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  if(Curl_uint32_hash_count(&ctx->streams) == 1)
    cf_ngtcp2_proxy_setup_keep_alive(cf, data);

  return CURLE_OK;
}

static int cb_h3_proxy_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *user_data,
                                void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream;
  size_t skiplen;

  if(!ctx)
    return 0;
  stream = H3_PROXY_STREAM_CTX(ctx, data);
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

static int cb_h3_proxy_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream;
  bool tunnel_stream = FALSE;
  (void)conn;

  if(!ctx)
    return 0;
  stream = H3_PROXY_STREAM_CTX(ctx, data);
  tunnel_stream = (stream_id == proxy_ctx->tunnel.stream_id);
  /* we might be called by nghttp3 after we already cleaned up */
  if(!stream) {
    if(tunnel_stream) {
      proxy_ctx->tunnel.stream = NULL;
      proxy_ctx->tunnel.closed = TRUE;
    }
    return 0;
  }

  stream->closed = TRUE;
  stream->error3 = app_error_code;
  if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" PRId64 "] RESET: error %" PRIu64,
                H3_STREAM_ID(stream), stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] CLOSED", H3_STREAM_ID(stream));
  }
  if(tunnel_stream) {
    proxy_ctx->tunnel.stream = NULL;
    proxy_ctx->tunnel.closed = TRUE;
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_proxy_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t buflen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream;
  size_t nwritten;
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)stream3_id;

  if(!ctx)
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream = H3_PROXY_STREAM_CTX(ctx, data);
  if(!stream) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  stream->tun_data_recvd += (curl_off_t)buflen;
  CURL_TRC_CF(data, cf, "[cb_h3_proxy_recv_data] "
              "[%" PRIu64 "] DATA len=%zu, total=%zd",
              H3_STREAM_ID(stream), buflen, stream->tun_data_recvd);

  result = Curl_bufq_write(&proxy_ctx->inbufq, buf, buflen, &nwritten);
  if(result || (nwritten < buflen)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  /* DATA has been moved into our local recv buffer. Give QUIC read
   * credit back so long transfers over proxy tunnels do not stall on
   * stream/connection flow-control limits. */
  ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream->id, buflen);
  ngtcp2_conn_extend_max_offset(ctx->qconn, buflen);

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_proxy_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
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

static int cb_h3_proxy_recv_header(nghttp3_conn *conn, int64_t sid,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  int64_t stream_id = sid;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream;
  CURLcode result = CURLE_OK;
  int http_status;
  struct http_resp *resp;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;

  /* stream_user_data might be NULL for control streams */
  if(!data) {
    /* Silently ignore headers on streams without user data (control, etc) */
    return 0;
  }

  if(!ctx)
    return 0;
  stream = H3_PROXY_STREAM_CTX(ctx, data);
  if(!stream) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] recv_header: stream lookup "
                "failed for data=%p mid=%u",
                stream_id, (void *)data, data ? data->mid : 0);
  }

  /* we might have cleaned up this transfer already */
  if(!stream)
    return 0;

  if(proxy_ctx->tunnel.has_final_response) {
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
    resp->prev = proxy_ctx->tunnel.resp;
    proxy_ctx->tunnel.resp = resp;
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" PRId64 "] header: %.*s: %.*s",
                stream_id, (int)h3name.len, h3name.base,
                (int)h3val.len, h3val.base);
    result = Curl_dynhds_add(&proxy_ctx->tunnel.resp->headers,
      (const char *)h3name.base, h3name.len,
      (const char *)h3val.base, h3val.len);
    if(result) {
      return -1;
    }
  }
  return 0;
}

static int cb_h3_proxy_end_headers(nghttp3_conn *conn, int64_t sid,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  int64_t stream_id = sid;
  struct h3_proxy_stream_ctx *stream;
  (void)conn;
  (void)stream_id;
  (void)fin;

  /* stream_user_data might be NULL for control streams */
  if(!data) {
    /* Silently ignore for streams without user data */
    return 0;
  }

  if(!ctx)
    return 0;
  stream = H3_PROXY_STREAM_CTX(ctx, data);
  if(!stream) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] end_headers: stream lookup "
                "failed for data=%p mid=%u",
                stream_id, (void *)data, data ? data->mid : 0);
  }

  if(!stream)
    return 0;

  CURL_TRC_CF(data, cf, "[%" PRId64 "] end_headers, status=%d",
              stream_id, stream->status_code);

  if(!proxy_ctx->tunnel.has_final_response) {
    if(stream->status_code / 100 != 1) {
      proxy_ctx->tunnel.has_final_response = TRUE;
    }
  }

  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_proxy_stop_sending(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  (void)conn;

  (void)stream_user_data;

  if(ctx) {
    int rv = ngtcp2_conn_shutdown_stream_read(ctx->qconn, 0, sid,
                                              app_error_code);

    if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

static int cb_h3_proxy_reset_stream(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  int64_t stream_id = sid;
  int rv;
  (void)conn;

  if(!ctx)
    return 0;

  rv = ngtcp2_conn_shutdown_stream_write(ctx->qconn, 0, stream_id,
                                         app_error_code);
  CURL_TRC_CF(data, cf, "[%" PRId64 "] reset -> %d", stream_id, rv);
  if(stream_id == proxy_ctx->tunnel.stream_id) {
    proxy_ctx->tunnel.stream = NULL;
    proxy_ctx->tunnel.closed = TRUE;
  }
  if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static nghttp3_ssize
cb_h3_read_data_for_tunnel_stream(nghttp3_conn *conn, int64_t stream_id,
                                  nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream;
  size_t nwritten = 0;
  size_t nvecs = 0;
  const unsigned char *buf_base;
  (void)conn;
  (void)stream_id;
  (void)veccnt;

  if(!ctx)
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream = H3_PROXY_STREAM_CTX(ctx, data);

  if(!stream)
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
    DEBUGASSERT(nvecs > 0); /* we SHOULD have been be able to peek */
  }

  if(nwritten > 0 &&
     stream->upload_left != -1 &&
     (H3_STREAM_ID(stream) != proxy_ctx->tunnel.stream_id))
    stream->upload_left -= nwritten;

  /* When we stopped sending and everything in `sendbuf` is "in flight",
   * we are at the end of the request body. */
  /* We should NOT set send_closed = TRUE for tunnel stream */
  if(stream->upload_left == 0 &&
     (H3_STREAM_ID(stream) != proxy_ctx->tunnel.stream_id)) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }

  else if(!nwritten) {
    /* Not EOF, and nothing to give, we signal WOULDBLOCK. */
    CURL_TRC_CF(data, cf, "[%" PRId64 "] read req body -> AGAIN",
                H3_STREAM_ID(stream));
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" PRId64 "] read req body -> "
              "%d vecs%s with %zd (buffered=%zu, left=%" FMT_OFF_T ")",
              H3_STREAM_ID(stream), (int)nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf),
              stream->upload_left);
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
#ifdef NGHTTP3_CALLBACKS_V2 /* nghttp3 v1.11.0+ */
  NULL, /* recv_origin */
  NULL, /* end_origin */
  NULL, /* rand */
#endif /* NGHTTP3_CALLBACKS_V2 */
#ifdef NGHTTP3_CALLBACKS_V3  /* nghttp3 v1.14.0+ */
  NULL, /* recv_settings2 */
#endif /* NGHTTP3_CALLBACKS_V3 */
};

#if NGTCP2_VERSION_NUM < 0x011100
struct cf_ngtcp2_proxy_sfind_ctx {
  int64_t stream_id;
  struct h3_proxy_stream_ctx *stream;
  uint32_t mid;
};

static bool cf_ngtcp2_proxy_sfind(uint32_t mid, void *value,
                                  void *user_data)
{
  struct cf_ngtcp2_proxy_sfind_ctx *fctx = user_data;
  struct h3_proxy_stream_ctx *stream = value;

  if(fctx->stream_id == H3_STREAM_ID(stream)) {
    fctx->mid = mid;
    fctx->stream = stream;
    return FALSE;
  }
  return TRUE; /* continue */
}

static struct h3_proxy_stream_ctx *
cf_ngtcp2_proxy_get_stream(struct cf_ngtcp2_proxy_ctx *ctx, int64_t stream_id)
{
  struct cf_ngtcp2_proxy_sfind_ctx fctx;
  fctx.stream_id = stream_id;
  fctx.stream = NULL;
  Curl_uint32_hash_visit(&ctx->streams, cf_ngtcp2_proxy_sfind, &fctx);
  return fctx.stream;
}
#else
static struct h3_proxy_stream_ctx *
cf_ngtcp2_proxy_get_stream(struct cf_ngtcp2_proxy_ctx *ctx, int64_t stream_id)
{
  struct Curl_easy *data =
    ngtcp2_conn_get_stream_user_data(ctx->qconn, stream_id);

  if(!data) {
    return NULL;
  }
  return H3_PROXY_STREAM_CTX(ctx, data);
}
#endif /* NGTCP2_VERSION_NUM < 0x011100 */

static CURLcode cf_ngtcp2_h3conn_init(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
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

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &ctrl_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 control stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = nghttp3_conn_bind_control_stream(ctx->h3conn, ctrl_stream_id);
  if(rc) {
    failf(data, "error binding HTTP/3 control stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_enc_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 qpack encoding stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_dec_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 qpack decoding stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = nghttp3_conn_bind_qpack_streams(ctx->h3conn, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if(rc) {
    failf(data, "error binding HTTP/3 qpack streams: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  CURL_TRC_CF(data, cf, "HTTP/3 connection initialized");
  return CURLE_OK;
}

static int cb_ngtcp2_proxy_handshake_completed(ngtcp2_conn *tconn,
                                               void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data;

  (void)tconn;
  DEBUGASSERT(ctx);
  data = CF_DATA_CURRENT(cf);
  DEBUGASSERT(data);
  if(!ctx || !data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  ctx->handshake_at = *Curl_pgrs_now(data);
  ctx->tls_handshake_complete = TRUE;
  Curl_vquic_report_handshake(&ctx->tls, cf, data);

  ctx->tls_vrfy_result = Curl_vquic_tls_verify_peer(&ctx->tls, cf,
                                                    data, &ctx->peer);
#ifdef CURLVERBOSE
  if(Curl_trc_is_verbose(data)) {
    const ngtcp2_transport_params *rp;
    rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
    CURL_TRC_CF(data, cf, "handshake complete after %" FMT_TIMEDIFF_T
                "ms, remote transport[max_udp_payload=%" PRIu64
                ", initial_max_data=%" PRIu64
                "]",
               curlx_ptimediff_ms(&ctx->handshake_at, &ctx->started_at),
               rp->max_udp_payload_size, rp->initial_max_data);
  }
#endif

  /* In case of earlydata, where we simulate being connected, update
   * the handshake time when we really did connect */
  if(ctx->use_earlydata)
    Curl_pgrsTimeWas(data, TIMER_APPCONNECT, ctx->handshake_at);
  if(ctx->use_earlydata) {
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA)
    ctx->earlydata_accepted =
      (SSL_get_early_data_status(ctx->tls.ossl.ssl) !=
       SSL_EARLY_DATA_REJECTED);
#endif
#ifdef USE_GNUTLS
    int flags = gnutls_session_get_flags(ctx->tls.gtls.session);
    ctx->earlydata_accepted = !!(flags & GNUTLS_SFLAGS_EARLY_DATA);
#endif /* USE_GNUTLS */
#ifdef USE_WOLFSSL
#ifdef WOLFSSL_EARLY_DATA
    ctx->earlydata_accepted =
      (wolfSSL_get_early_data_status(ctx->tls.wssl.ssl) !=
       WOLFSSL_EARLY_DATA_REJECTED);
#else
    DEBUGASSERT(0); /* should not come here if ED is disabled. */
    ctx->earlydata_accepted = FALSE;
#endif /* WOLFSSL_EARLY_DATA */
#endif /* USE_WOLFSSL */
    CURL_TRC_CF(data, cf, "server did%s accept %zu bytes of early data",
                ctx->earlydata_accepted ? "" : " not", ctx->earlydata_skip);
    Curl_pgrsEarlyData(data, ctx->earlydata_accepted ?
                              (curl_off_t)ctx->earlydata_skip :
                             -(curl_off_t)ctx->earlydata_skip);
  }

  /* Initialize HTTP/3 connection after successful handshake */
  if(!ctx->h3conn) {
    CURLcode result = cf_ngtcp2_h3conn_init(cf, data);
    if(result) {
      CURL_TRC_CF(data, cf, "HTTP/3 initialization failed: %d", result);
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

static int cb_ngtcp2_recv_stream_data(ngtcp2_conn *tconn, uint32_t flags,
                                      int64_t sid, uint64_t offset,
                                      const uint8_t *buf, size_t buflen,
                                      void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  int64_t stream_id = (int64_t)sid;
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
    CURL_TRC_CF(data, cf, "[%" PRId64 "] read_stream(len=%zu) -> %zd",
                stream_id, buflen, nconsumed);
  if(nconsumed < 0) {
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(data && stream) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] error on known stream, "
                  "reset=%d, closed=%d",
                  stream_id, stream->reset, stream->closed);
    }
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* number of bytes inside buflen which consists of framing overhead
   * including QPACK HEADERS. In other words, it does not consume payload of
   * DATA frame. */
  if(nconsumed) {
    ngtcp2_conn_extend_max_stream_offset(tconn, stream_id,
                                         (uint64_t)nconsumed);
    ngtcp2_conn_extend_max_offset(tconn, (uint64_t)nconsumed);
  }

  return 0;
}

static int cb_ngtcp2_acked_stream_data_offset(ngtcp2_conn *tconn,
                                              int64_t stream_id,
                                              uint64_t offset,
                                              uint64_t datalen,
                                              void *user_data,
                                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
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

static int cb_ngtcp2_stream_close(ngtcp2_conn *tconn, uint32_t flags,
                                  int64_t sid, uint64_t app_error_code,
                                  void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  int64_t stream_id = (int64_t)sid;
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
  CURL_TRC_CF(data, cf, "[%" PRId64 "] quic close(app_error=%"
              PRIu64 ") -> %d", stream_id, (uint64_t)app_error_code,
              rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    cf_ngtcp2_proxy_h3_err_set(cf, data, rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_ngtcp2_extend_max_local_streams_bidi(ngtcp2_conn *tconn,
                                                   uint64_t max_streams,
                                                   void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)tconn;
  ctx->max_bidi_streams = max_streams;
  if(data)
    CURL_TRC_CF(data, cf, "max bidi streams now %" PRIu64
                ", used %" PRIu64, (uint64_t)ctx->max_bidi_streams,
                (uint64_t)ctx->used_bidi_streams);
  return 0;
}

static void cb_ngtcp2_rand(uint8_t *dest, size_t destlen,
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

/* for ngtcp2 <v1.22.0 */
static int cb_ngtcp2_get_new_connection_id(ngtcp2_conn *tconn, ngtcp2_cid *cid,
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

#ifdef NGTCP2_CALLBACKS_V3  /* ngtcp2 v1.22.0+ */
static int cb_ngtcp2_get_new_connection_id2(ngtcp2_conn *tconn,
  ngtcp2_cid *cid, struct ngtcp2_stateless_reset_token *token,
  size_t cidlen, void *user_data)
{
  CURLcode result;
  (void)tconn;
  (void)user_data;

  result = Curl_rand(NULL, cid->data, cidlen);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;

  result = Curl_rand(NULL, token->data, sizeof(token->data));
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}
#endif

static int cb_ngtcp2_stream_reset(ngtcp2_conn *tconn, int64_t sid,
                                  uint64_t final_size, uint64_t app_error_code,
                                  void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  int64_t stream_id = (int64_t)sid;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;
  (void)data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  CURL_TRC_CF(data, cf, "[%" PRId64 "] reset -> %d", stream_id, rv);
  if(stream_id == proxy_ctx->tunnel.stream_id) {
    proxy_ctx->tunnel.stream = NULL;
    proxy_ctx->tunnel.closed = TRUE;
  }
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_ngtcp2_extend_max_stream_data(ngtcp2_conn *tconn,
                                            int64_t stream_id,
                                            uint64_t max_data, void *user_data,
                                            void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *s_data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  int rv;
  (void)tconn;
  (void)max_data;

  rv = nghttp3_conn_unblock_stream(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  stream = H3_PROXY_STREAM_CTX(ctx, s_data);
  if(stream && stream->quic_flow_blocked) {
    CURL_TRC_CF(s_data, cf, "[%" PRId64 "] unblock quic flow",
                (int64_t)stream_id);
    stream->quic_flow_blocked = FALSE;
    Curl_multi_mark_dirty(s_data);
  }
  return 0;
}

static int cb_ngtcp2_stream_stop_sending(ngtcp2_conn *tconn, int64_t stream_id,
                                         uint64_t app_error_code,
                                         void *user_data,
                                         void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
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

static int cb_ngtcp2_recv_rx_key(ngtcp2_conn *tconn,
                                 ngtcp2_encryption_level level,
                                 void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  (void)tconn;

  if(level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
    return 0;

  DEBUGASSERT(ctx);
  DEBUGASSERT(data);
  if(ctx && data && !ctx->h3conn) {
    if(cf_ngtcp2_h3conn_init(cf, data))
      return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

#if defined(_MSC_VER) && defined(_DLL)
#pragma warning(push)
#pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

static ngtcp2_callbacks ngtcp2_proxy_callbacks = {
  ngtcp2_crypto_client_initial_cb,
  NULL, /* recv_client_initial */
  ngtcp2_crypto_recv_crypto_data_cb,
  cb_ngtcp2_proxy_handshake_completed,
  NULL, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_ngtcp2_recv_stream_data,
  cb_ngtcp2_acked_stream_data_offset,
  NULL, /* stream_open */
  cb_ngtcp2_stream_close,
  NULL, /* recv_stateless_reset */
  ngtcp2_crypto_recv_retry_cb,
  cb_ngtcp2_extend_max_local_streams_bidi,
  NULL, /* extend_max_local_streams_uni */
  cb_ngtcp2_rand,
  cb_ngtcp2_get_new_connection_id, /* for ngtcp2 <v1.22.0 */
  NULL, /* remove_connection_id */
  ngtcp2_crypto_update_key_cb,
  NULL, /* path_validation */
  NULL, /* select_preferred_addr */
  cb_ngtcp2_stream_reset,
  NULL, /* extend_max_remote_streams_bidi */
  NULL, /* extend_max_remote_streams_uni */
  cb_ngtcp2_extend_max_stream_data,
  NULL, /* dcid_status */
  NULL, /* handshake_confirmed */
  NULL, /* recv_new_token */
  ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  NULL, /* recv_datagram */
  NULL, /* ack_datagram */
  NULL, /* lost_datagram */
  ngtcp2_crypto_get_path_challenge_data_cb,
  cb_ngtcp2_stream_stop_sending,
  NULL, /* version_negotiation */
  cb_ngtcp2_recv_rx_key, /* recv_rx_key */
  NULL, /* recv_tx_key */
  NULL, /* early_data_rejected */
#ifdef NGTCP2_CALLBACKS_V2  /* ngtcp2 v1.14.0+ */
  NULL, /* begin_path_validation */
#endif /* NGTCP2_CALLBACKS_V2 */
#ifdef NGTCP2_CALLBACKS_V3  /* ngtcp2 v1.22.0+ */
  NULL, /* recv_stateless_reset2 */
  cb_ngtcp2_get_new_connection_id2, /* get_new_connection_id2 */
  NULL, /* dcid_status2 */
  ngtcp2_crypto_get_path_challenge_data2_cb, /* get_path_challenge_data2 */
#endif /* NGTCP2_CALLBACKS_V3 */
};

#if defined(_MSC_VER) && defined(_DLL)
#pragma warning(pop)
#endif

static CURLcode cf_ngtcp2_recv_pkts_proxy(const unsigned char *buf,
                                          size_t buflen, size_t gso_size,
                                          struct sockaddr_storage *remote_addr,
                                          socklen_t remote_addrlen, int ecn,
                                          void *userp)
{
  struct proxy_pkt_io_ctx *pktx = userp;
  struct cf_h3_proxy_ctx *proxy_ctx = pktx->cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  ngtcp2_pkt_info pi;
  ngtcp2_path path;
  size_t offset, pktlen;
  int rv;

  if(ecn)
    CURL_TRC_CF(pktx->data, pktx->cf, "vquic_recv(len=%zu, gso=%zu, ecn=%x)",
                buflen, gso_size, ecn);
  ngtcp2_addr_init(&path.local, (struct sockaddr *)&ctx->q.local_addr,
                   (socklen_t)ctx->q.local_addrlen);
  ngtcp2_addr_init(&path.remote, (struct sockaddr *)remote_addr,
                   remote_addrlen);
  pi.ecn = (uint8_t)ecn;

  for(offset = 0; offset < buflen; offset += gso_size) {
    pktlen = ((offset + gso_size) <= buflen) ? gso_size : (buflen - offset);
    rv = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi,
                              buf + offset, pktlen, pktx->ts);
    if(rv) {
      CURL_TRC_CF(pktx->data, pktx->cf, "ingress, read_pkt -> %s (%d)",
                  ngtcp2_strerror(rv), rv);
      cf_ngtcp2_proxy_err_set(pktx->cf, pktx->data, rv);

      if(rv == NGTCP2_ERR_CRYPTO)
        /* this is a "TLS problem", but a failed certificate verification
           is a common reason for this */
        return CURLE_PEER_FAILED_VERIFICATION;
      return CURLE_RECV_ERROR;
    }
  }
  return CURLE_OK;
}

static CURLcode proxy_h3_progress_ingress_ngtcp2(struct Curl_cfilter *cf,
                                                 struct Curl_easy *data,
                                                 struct proxy_pkt_io_ctx *pktx)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct proxy_pkt_io_ctx local_pktx;
  CURLcode result = CURLE_OK;

  if(!ctx)
    return CURLE_RECV_ERROR;
  if(!data || !data->multi)
    return CURLE_RECV_ERROR;

  if(!pktx) {
    proxy_pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    proxy_pktx_update_time(pktx, cf);
    ngtcp2_path_storage_zero(&pktx->ps);
  }

  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    return result;

  /* Check if next filter is UDP or a tunnel */
  if(cf->next->cft == &Curl_cft_udp) {
    /* Direct UDP connection to proxy - use vquic_recv_packets */
    return vquic_recv_packets(cf, data, &ctx->q, 1000,
                              cf_ngtcp2_recv_pkts_proxy, pktx);
  }
  else {
    /* CONNECT-UDP tunnel through HTTP/1.1 or HTTP/2 proxy */
    /* Read packets from the tunnel */
    unsigned char *buf;
    size_t max_udp_payload = PROXY_QUIC_TUNNEL_INBUF_SIZE;
    size_t pkt_limit = PROXY_QUIC_INGRESS_PKT_LIMIT;
    size_t nread;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;

    if(ctx->qconn) {
      size_t max_path_payload;
      max_path_payload =
        ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
      if(max_path_payload > max_udp_payload)
        max_udp_payload = max_path_payload;
    }

    if(ctx->tunnel_inbuf_len < max_udp_payload) {
      unsigned char *newbuf =
        (unsigned char *)curlx_realloc(ctx->tunnel_inbuf, max_udp_payload);
      if(!newbuf)
        return CURLE_OUT_OF_MEMORY;
      ctx->tunnel_inbuf = newbuf;
      ctx->tunnel_inbuf_len = max_udp_payload;
    }
    buf = ctx->tunnel_inbuf;

    while(pkt_limit--) {
      result = Curl_conn_cf_recv(cf->next, data, (char *)buf,
                                 ctx->tunnel_inbuf_len, &nread);
      if(result == CURLE_AGAIN) {
        /* No more data available */
        return CURLE_OK;
      }
      if(result) {
        CURL_TRC_CF(data, cf, "ingress, recv from tunnel failed: %d",
                    result);
        return result;
      }
      if(nread == 0) {
        /* Connection closed */
        return CURLE_OK;
      }

      /* Use the connected path's remote address */
      memcpy(&remote_addr, ctx->connected_path.remote.addr,
             ctx->connected_path.remote.addrlen);
      remote_addrlen = (socklen_t)ctx->connected_path.remote.addrlen;

      /* Process the received packet */
      result = cf_ngtcp2_recv_pkts_proxy(buf, nread, nread,
                                         &remote_addr, remote_addrlen,
                                         0, pktx);
      if(result)
        return result;

      if(!ctx->q.got_first_byte) {
        ctx->q.got_first_byte = TRUE;
        ctx->q.first_byte_at = ctx->q.last_op;
      }
      ctx->q.last_io = ctx->q.last_op;
    }
    return CURLE_OK;
  }
}

/**
 * Read a network packet to send from ngtcp2 into `buf`.
 * Return number of bytes written or -1 with *err set.
 */
static CURLcode proxy_read_pkt_to_send(void *userp,
                                 unsigned char *buf, size_t buflen,
                                 size_t *pnread)
{
  struct proxy_pkt_io_ctx *x = userp;
  struct cf_h3_proxy_ctx *proxy_ctx = x->cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  nghttp3_vec vec[16];
  nghttp3_ssize veccnt;
  ngtcp2_ssize ndatalen;
  uint32_t flags;
  int64_t stream_id;
  int fin;
  ssize_t n;

  *pnread = 0;
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
  for(;;) {

    if(ctx->h3conn && ngtcp2_conn_get_max_data_left(ctx->qconn)) {
      veccnt = nghttp3_conn_writev_stream(ctx->h3conn, &stream_id, &fin, vec,
                                          CURL_ARRAYSIZE(vec));
      if(veccnt < 0) {
        failf(x->data, "nghttp3_conn_writev_stream returned error: %s",
              nghttp3_strerror((int)veccnt));
        cf_ngtcp2_proxy_h3_err_set(x->cf, x->data, (int)veccnt);
        return CURLE_SEND_ERROR;
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
      return CURLE_AGAIN;
    }
    else if(n < 0) {
      switch(n) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
        struct h3_proxy_stream_ctx *stream = NULL;
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_block_stream(ctx->h3conn, stream_id);
        CURL_TRC_CF(x->data, x->cf, "[%" PRId64 "] block quic flow",
                    (int64_t)stream_id);
        stream = cf_ngtcp2_proxy_get_stream(ctx, stream_id);
        if(stream) /* it might be not one of our h3 streams? */
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
        cf_ngtcp2_proxy_err_set(x->cf, x->data, (int)n);
        return CURLE_SEND_ERROR;
      }
    }

    if(ndatalen >= 0) {
      /* we add the amount of data bytes to the flow windows */
      int rv = nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, ndatalen);
      if(rv) {
        failf(x->data, "nghttp3_conn_add_write_offset returned error: %s",
              nghttp3_strerror(rv));
        return CURLE_SEND_ERROR;
      }
    }

    if(n > 0) {
      /* packet assembled, leave */
      *pnread = (size_t)n;
      return CURLE_OK;
    }
  }
}

static CURLcode proxy_h3_progress_egress_ngtcp2(struct Curl_cfilter *cf,
                                                struct Curl_easy *data,
                                                struct proxy_pkt_io_ctx *pktx)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  size_t nread;
  size_t max_payload_size, path_max_payload_size;
  size_t pktcnt = 0;
  size_t gsolen = 0;  /* this disables gso until we have a clue */
  size_t send_quantum;
  CURLcode curlcode;
  struct proxy_pkt_io_ctx local_pktx;

  if(!pktx) {
    proxy_pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    proxy_pktx_update_time(pktx, cf);
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

  /* In UDP, there is a maximum theoretical packet payload length and
   * a minimum payload length that is "guaranteed" to work.
   * To detect if this minimum payload can be increased, ngtcp2 sends
   * now and then a packet payload larger than the minimum. It that
   * is ACKed by the peer, both parties know that it works and
   * the subsequent packets can use a larger one.
   * This is called PMTUD (Path Maximum Transmission Unit Discovery).
   * Since a PMTUD might be rejected right on send, we do not want it
   * be followed by other packets of lesser size. Because those would
   * also fail then. If we detect a PMTUD while buffering, we flush.
   */
  max_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(ctx->qconn);
  path_max_payload_size =
      ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
  send_quantum = ngtcp2_conn_get_send_quantum(ctx->qconn);
  CURL_TRC_CF(data, cf, "egress, collect and send packets, quantum=%zu",
              send_quantum);
  for(;;) {
    /* add the next packet to send, if any, to our buffer */
    curlcode = Curl_bufq_sipn(&ctx->q.sendbuf, max_payload_size,
                              proxy_read_pkt_to_send, pktx, &nread);
    if(curlcode == CURLE_AGAIN)
      break;
    else if(curlcode)
      return curlcode;
    else {
      size_t buflen = Curl_bufq_len(&ctx->q.sendbuf);
      if((buflen >= send_quantum) ||
         ((buflen + gsolen) >= ctx->q.sendbuf.chunk_size))
         break;
      DEBUGASSERT(nread > 0);
      ++pktcnt;
      if(pktcnt == 1) {
        /* first packet in buffer. This is either of a known, "good"
         * payload size or it is a PMTUD. We shall see. */
        gsolen = nread;
      }
      else if(nread > gsolen ||
              (gsolen > path_max_payload_size && nread != gsolen)) {
        /* The added packet is a PMTUD *or* the one(s) before the
         * added were PMTUD and the last one is smaller.
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
      }
      else if(nread < gsolen) {
        /* Reached capacity of our buffer *or*
         * last add was shorter than the previous ones, flush */
        break;
      }
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* time to send */
    CURL_TRC_CF(data, cf, "egress, send collected %zu packets in %zu bytes",
                pktcnt, Curl_bufq_len(&ctx->q.sendbuf));
    curlcode = vquic_send(cf, data, &ctx->q, gsolen);
    if(curlcode) {
      if(curlcode == CURLE_AGAIN) {
        Curl_expire(data, 1, EXPIRE_QUIC);
        return CURLE_OK;
      }
      return curlcode;
    }
    proxy_pktx_update_time(pktx, cf);
    ngtcp2_conn_update_pkt_tx_time(ctx->qconn, pktx->ts);
  }
  return CURLE_OK;
}

static CURLcode cf_ngtcp2_proxy_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data, bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct cf_call_data save;
  struct proxy_pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(!cf->next) {
    Curl_bufq_reset(&ctx->q.sendbuf);
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;
  proxy_pktx_init(&pktx, cf, data);

  if(!ctx->shutdown_started) {
    char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    ngtcp2_ssize nwritten;

    if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
      result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
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

    DEBUGASSERT(Curl_bufq_is_empty(&ctx->q.sendbuf));
    ctx->shutdown_started = TRUE;
    nwritten = ngtcp2_conn_write_connection_close(
      ctx->qconn, NULL, /* path */
      NULL, /* pkt_info */
      (uint8_t *)buffer, sizeof(buffer),
      &ctx->last_error, pktx.ts);
    CURL_TRC_CF(data, cf, "start shutdown(err_type=%d, err_code=%"
                PRIu64 ") -> %zd", ctx->last_error.type,
                (uint64_t)ctx->last_error.error_code, (ssize_t)nwritten);
    /* there are cases listed in ngtcp2 documentation where this call
     * may fail. Since we are doing a connection shutdown as graceful
     * as we can, such an error is ignored here. */
    if(nwritten > 0) {
      /* Ignore amount written. sendbuf was empty and has always room for
       * NGTCP2_MAX_UDP_PAYLOAD_SIZE. It can only completely fail, in which
       * case `result` is set non zero. */
      size_t n;
      result = Curl_bufq_write(&ctx->q.sendbuf, (const unsigned char *)buffer,
                               (size_t)nwritten, &n);
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
     * shutdowns. We are done. */
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
    result = CURLE_OK;
  }
out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_ngtcp2_proxy_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  bool done;
  cf_ngtcp2_proxy_shutdown(cf, data, &done);
}

static void cf_ngtcp2_proxy_close(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  if(ctx && ctx->qconn) {
    cf_ngtcp2_proxy_conn_close(cf, data);
    cf_ngtcp2_proxy_ctx_close(ctx);
    CURL_TRC_CF(data, cf, "close");
  }
  cf->connected = FALSE;
  CF_DATA_RESTORE(cf, save);
}

static void cf_ngtcp2_proxy_stream_close(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_proxy_stream_ctx  *stream)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  DEBUGASSERT(data);
  DEBUGASSERT(stream);

  if(stream->id == proxy_ctx->tunnel.stream_id) {
    proxy_ctx->tunnel.stream = NULL;
    proxy_ctx->tunnel.closed = TRUE;
  }

  if(ctx->h3conn)
    nghttp3_conn_set_stream_user_data(ctx->h3conn, stream->id, NULL);
  if(ctx->qconn)
    ngtcp2_conn_set_stream_user_data(ctx->qconn, stream->id, NULL);

  if(!stream->closed && ctx->qconn && ctx->h3conn) {
    CURLcode result;

    stream->closed = TRUE;
    (void)ngtcp2_conn_shutdown_stream(ctx->qconn, 0, stream->id,
                                      NGHTTP3_H3_REQUEST_CANCELLED);
    result = proxy_h3_progress_egress_ngtcp2(cf, data, NULL);
    if(result)
      CURL_TRC_CF(data, cf, "[%" PRId64 "] cancel stream -> %d",
                  stream->id, result);
  }
}

/**
 * Connection maintenance like timeouts on packet ACKs etc. are done by us, not
 * the OS like for TCP. POLL events on the socket therefore are not
 * sufficient.
 * ngtcp2 tells us when it wants to be invoked again. We handle that via
 * the `Curl_expire()` mechanisms.
 */
static CURLcode check_and_set_expiry_ngtcp2(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            struct proxy_pkt_io_ctx *pktx)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct proxy_pkt_io_ctx local_pktx;
  ngtcp2_tstamp expiry;

  if(!ctx)
    return CURLE_OK;

  if(!pktx) {
    proxy_pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    proxy_pktx_update_time(pktx, cf);
  }

  expiry = ngtcp2_conn_get_expiry(ctx->qconn);
  if(expiry != UINT64_MAX) {
    if(expiry <= pktx->ts) {
      CURLcode result;
      int rv = ngtcp2_conn_handle_expiry(ctx->qconn, pktx->ts);
      if(rv) {
        failf(data, "ngtcp2_conn_handle_expiry returned error: %s",
              ngtcp2_strerror(rv));
        cf_ngtcp2_proxy_err_set(cf, data, rv);
        return CURLE_SEND_ERROR;
      }
      result = proxy_h3_progress_ingress_ngtcp2(cf, data, pktx);
      if(result)
        return result;
      result = proxy_h3_progress_egress_ngtcp2(cf, data, pktx);
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

static ssize_t proxy_recv_closed_stream(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_proxy_stream_ctx *stream,
                                  CURLcode *err)
{
  ssize_t nread = -1;

  (void)cf;
  if(stream->reset) {
    failf(data, "HTTP/3 stream %" PRId64 " reset by server", stream->id);
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
  *err = CURLE_OK;
  nread = 0;

out:
  return nread;
}

static struct h3_proxy_stream_ctx *
h3_proxy_resolve_send_stream(struct cf_h3_proxy_ctx *proxy_ctx,
                             struct cf_ngtcp2_proxy_ctx *ctx,
                             struct Curl_easy *data)
{
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

  if(stream)
    return stream;

  /* send can be driven by a different easy handle during shutdown */
  if(proxy_ctx->tunnel.stream && !proxy_ctx->tunnel.closed) {
    return proxy_ctx->tunnel.stream;
  }
  return NULL;
}

static CURLcode h3_proxy_sendbuf_add(struct Curl_easy *data,
                                     struct h3_proxy_stream_ctx *stream,
                                     const uint8_t *buf, size_t len,
                                     size_t *pnwritten)
{
  CURLcode result;

  (void)data;
  *pnwritten = 0;
  result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
  return result;
}

static CURLcode cf_h3_proxy_send(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const uint8_t *buf, size_t len,
                                 bool eos, size_t *pnwritten)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream = NULL;
  struct cf_call_data save;
  struct proxy_pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  proxy_pktx_init(&pktx, cf, data);
  *pnwritten = 0;

  /* handshake verification failed in callback, do not send anything */
  if(ctx->tls_vrfy_result) {
    result = ctx->tls_vrfy_result;
    goto denied;
  }

  (void)eos; /* use for stream EOF and block handling */
  result = proxy_h3_progress_ingress_ngtcp2(cf, data, &pktx);
  if(result)
    goto out;

  stream = h3_proxy_resolve_send_stream(proxy_ctx, ctx, data);
  if(!stream) {
    result = CURLE_SEND_ERROR;
    goto denied;
  }

  if(proxy_ctx->tunnel.closed) {
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
    result = h3_proxy_sendbuf_add(data, stream, buf, len, pnwritten);
    CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_send, add to "
                "sendbuf(len=%zu) -> %d, %zu",
                stream->id, len, result, *pnwritten);
    if(result)
      goto out;
    (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
  }

  if(*pnwritten > 0 && !ctx->tls_handshake_complete && ctx->use_earlydata)
    ctx->earlydata_skip += *pnwritten;

  DEBUGASSERT(!result);
  result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);

out:
  result = Curl_1st_fatal(result,
                          check_and_set_expiry_ngtcp2(cf, data, &pktx));
denied:
  CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, result, *pnwritten);
  CF_DATA_RESTORE(cf, save);
  return result;
}

/* incoming data frames on the h3 stream */
static CURLcode cf_h3_proxy_recv(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 char *buf, size_t len, size_t *pnread)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  struct proxy_pkt_io_ctx pktx;
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

  proxy_pktx_init(&pktx, cf, data);

  if(!stream || ctx->shutdown_started) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(!Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
    result = Curl_bufq_cread(&proxy_ctx->inbufq,
                            buf, len, pnread);
    if(result)
      goto out;
  }

  result = proxy_h3_progress_ingress_ngtcp2(cf, data, &pktx);
  if(result)
    goto out;

  /* inbufq had nothing before, maybe after progressing ingress? */
  if(!*pnread && !Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
    result = Curl_bufq_cread(&proxy_ctx->inbufq,
                             buf, len, pnread);
    if(result) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] read inbufq(len=%zu) "
                            "-> %zd, %d",
                  stream->id, len, *pnread, result);
      goto out;
    }
  }

  if(*pnread) {
    Curl_multi_mark_dirty(data);
  }
  else {
    if(stream->xfer_result) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] xfer write failed",
                  stream->id);
      cf_ngtcp2_proxy_stream_close(cf, data, stream);
      result = stream->xfer_result;
      goto out;
    }
    else if(stream->closed) {
      ssize_t nread = proxy_recv_closed_stream(cf, data, stream, &result);
      if(nread > 0)
        *pnread = (size_t)nread;
      goto out;
    }
    result = CURLE_AGAIN;
  }

out:
  result = Curl_1st_fatal(result,
                          proxy_h3_progress_egress_ngtcp2(cf, data, &pktx));
  result = Curl_1st_fatal(result,
                          check_and_set_expiry_ngtcp2(cf, data, &pktx));
denied:
  CURL_TRC_CF(data, cf, "[%" PRId64 "] cf_recv(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, result, *pnread);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void proxy_h3_submit(int64_t *pstream_id,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct httpreq *req,
                            CURLcode *err)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream = NULL;

  struct dynhds h2_headers;
  nghttp3_nv *nva = NULL;
  size_t nheader;

  int rc = 0;
  unsigned int i;
  nghttp3_data_reader reader;
  nghttp3_data_reader *preader = NULL;

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);
  *err = Curl_http_req_to_h2(&h2_headers, req, data);
  if(*err)
    goto out;

  *err = h3_proxy_data_setup(cf, data);
  if(*err)
    goto out;

  if(!ctx) {
    *err = CURLE_FAILED_INIT;
    goto out;
  }

  stream = H3_PROXY_STREAM_CTX(ctx, data);

  DEBUGASSERT(stream);
  if(!stream) {
    *err = CURLE_FAILED_INIT;
    goto out;
  }

  nheader = Curl_dynhds_count(&h2_headers);
  nva = curlx_malloc(sizeof(nghttp3_nv) * nheader);
  if(!nva) {
    *err = CURLE_OUT_OF_MEMORY;
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
    rv = ngtcp2_conn_open_bidi_stream(ctx->qconn, &sid, data);
    if(rv) {
      failf(data, "cannot get bidi streams: %s", ngtcp2_strerror(rv));
      *err = CURLE_SEND_ERROR;
      goto out;
    }
    stream->id = (int64_t)sid;
    ++ctx->used_bidi_streams;

    /* Set stream user data in ngtcp2 connection for callbacks */
    rv = ngtcp2_conn_set_stream_user_data(ctx->qconn, sid, data);
    if(rv) {
      failf(data, "cannot set stream user data: %s", ngtcp2_strerror(rv));
      *err = CURLE_SEND_ERROR;
      goto out;
    }
    proxy_ctx->tunnel.stream = stream;
    CURL_TRC_CF(data, cf, "[%" PRId64 "] opened bidi stream", sid);
  }

  /* CONNECT-UDP request stream remains open for capsules, no fixed EOF. */
  stream->upload_left = -1;
  stream->send_closed = 0;
  reader.read_data = cb_h3_read_data_for_tunnel_stream;
  preader = &reader;

  rc = nghttp3_conn_submit_request(ctx->h3conn, H3_STREAM_ID(stream),
                                   nva, nheader, preader, data);

  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%" PRId64 "] failed to send, "
                            "connection is closing",
                  H3_STREAM_ID(stream));
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" PRId64 "] failed to send -> %d (%s)",
                  H3_STREAM_ID(stream), rc, nghttp3_strerror(rc));
      break;
    }
    *err = CURLE_SEND_ERROR;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    CURL_TRC_CF(data, cf, "[H3-PROXY] [%" PRId64 "] OPENED stream "
                "for %s", H3_STREAM_ID(stream),
                Curl_bufref_ptr(&data->state.url));
  }

out:
  curlx_free(nva);
  Curl_dynhds_free(&h2_headers);
  if(*err == CURLE_OK) {
    *pstream_id = H3_STREAM_ID(stream);
  }
}

static bool cf_h3_proxy_is_alive(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *input_pending)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  bool alive = FALSE;
  const ngtcp2_transport_params *rp;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  *input_pending = FALSE;

  if(!ctx || !ctx->qconn || ctx->shutdown_started)
    goto out;
  if(proxy_ctx->tunnel.closed)
    goto out;

  /* We do not announce a max idle timeout, but when the peer does
   * it closes the connection when it expires. */
  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(rp && rp->max_idle_timeout) {
    timediff_t idletime_ms =
      curlx_ptimediff_ms(Curl_pgrs_now(data), &ctx->q.last_io);
    if(idletime_ms > 0) {
      uint64_t max_idle_ms =
        (uint64_t)(rp->max_idle_timeout / NGTCP2_MILLISECONDS);
      if((uint64_t)idletime_ms > max_idle_ms)
        goto out;
    }
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
    if(!data || !data->multi) {
      alive = FALSE;
      goto out;
    }
    result = proxy_h3_progress_ingress_ngtcp2(cf, data, NULL);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result ? FALSE : TRUE;
  }

out:
  CF_DATA_RESTORE(cf, save);
  return alive;
}

static CURLcode cf_ngtcp2_proxy_query(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      int query, int *pres1, void *pres2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct cf_call_data save;

  if(!ctx)
    return cf->next ?
      cf->next->cft->query(cf->next, data, query, pres1, pres2) :
      CURLE_UNKNOWN_OPTION;

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

static CURLcode cf_ngtcp2_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                               struct Curl_easy *data,
                                               struct easy_pollset *ps)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  bool want_recv, want_send;
  CURLcode result = CURLE_OK;

  if(!ctx->qconn)
    return CURLE_OK;

  Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
  if(!want_send && !Curl_bufq_is_empty(&ctx->q.sendbuf))
    want_send = TRUE;

  if(want_recv || want_send) {
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    struct cf_call_data save;
    bool c_exhaust, s_exhaust;

    CF_DATA_SAVE(save, cf, data);
    c_exhaust = want_send && (!ngtcp2_conn_get_cwnd_left(ctx->qconn) ||
                !ngtcp2_conn_get_max_data_left(ctx->qconn));
    s_exhaust = want_send && stream && H3_STREAM_ID(stream) >= 0 &&
                stream->quic_flow_blocked;
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                 !Curl_bufq_is_empty(&ctx->q.sendbuf);

    result = Curl_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
  return result;
}

static CURLcode cf_h3_proxy_query(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   int query, int *pres1, void *pres2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;

  if(!proxy_ctx)
    return cf->next ?
      cf->next->cft->query(cf->next, data, query, pres1, pres2) :
      CURLE_UNKNOWN_OPTION;
  return cf_ngtcp2_proxy_query(cf, data, query, pres1, pres2);
}

static CURLcode cf_h3_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct easy_pollset *ps)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;

  if(!proxy_ctx)
    return cf->next ?
      cf->next->cft->adjust_pollset(cf->next, data, ps) :
      CURLE_OK;
  return cf_ngtcp2_proxy_adjust_pollset(cf, data, ps);
}

static bool cf_h3_proxy_data_pending(struct Curl_cfilter *cf,
                                     const struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  if(!proxy_ctx)
    return cf->next ?
      cf->next->cft->has_data_pending(cf->next, data) : FALSE;
  if(!Curl_bufq_is_empty(&proxy_ctx->inbufq))
    return TRUE;
  return cf->next ?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

#ifdef USE_OPENSSL
static int proxy_quic_ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid)
{
  ngtcp2_crypto_conn_ref *cref;
  struct Curl_cfilter *cf;
  struct cf_h3_proxy_ctx *proxy_ctx;
  struct cf_ngtcp2_proxy_ctx *ctx;
  struct Curl_easy *data;

  cref = (ngtcp2_crypto_conn_ref *)SSL_get_app_data(ssl);
  cf = cref ? cref->user_data : NULL;
  proxy_ctx = cf ? cf->ctx : NULL;
  ctx = proxy_ctx ? proxy_ctx->ngtcp2_ctx : NULL;
  data = cf ? CF_DATA_CURRENT(cf) : NULL;
  if(cf && data && ctx) {
    unsigned char *quic_tp = NULL;
    size_t quic_tp_len = 0;
#ifdef HAVE_OPENSSL_EARLYDATA
    ngtcp2_ssize tplen;
    uint8_t tpbuf[256];

    tplen = ngtcp2_conn_encode_0rtt_transport_params(ctx->qconn, tpbuf,
                                                     sizeof(tpbuf));
    if(tplen < 0)
      CURL_TRC_CF(data, cf, "error encoding 0RTT transport data: %s",
                  ngtcp2_strerror((int)tplen));
    else {
      quic_tp = (unsigned char *)tpbuf;
      quic_tp_len = (size_t)tplen;
    }
#endif /* HAVE_OPENSSL_EARLYDATA */
    Curl_ossl_add_session(cf, data, ctx->peer.scache_key, ssl_sessionid,
                          SSL_version(ssl), "h3", quic_tp, quic_tp_len);
  }
  return 0;
}
#endif /* USE_OPENSSL */

static CURLcode cf_ngtcp2_proxy_tls_ctx_setup(struct Curl_cfilter *cf,
                                              struct Curl_easy *data,
                                              void *user_data)
{
  struct curl_tls_ctx *ctx = user_data;

#ifdef USE_OPENSSL
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
  if(ngtcp2_crypto_boringssl_configure_client_context(ctx->ossl.ssl_ctx)
     != 0) {
    failf(data, "ngtcp2_crypto_boringssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#elif defined(OPENSSL_QUIC_API2)
  /* nothing to do */
#else
  if(ngtcp2_crypto_quictls_configure_client_context(ctx->ossl.ssl_ctx) != 0) {
    failf(data, "ngtcp2_crypto_quictls_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#endif
  if(Curl_ssl_scache_use(cf, data)) {
    SSL_CTX_set_session_cache_mode(ctx->ossl.ssl_ctx,
                                   SSL_SESS_CACHE_CLIENT |
                                   SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(ctx->ossl.ssl_ctx, proxy_quic_ossl_new_session_cb);
  }

#else
#error "ngtcp2 TLS backend not configured"
#endif /* USE_OPENSSL */

  return CURLE_OK;
}

static CURLcode cf_ngtcp2_proxy_on_session_reuse(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct alpn_spec *alpns,
                                           struct Curl_ssl_session *scs,
                                           bool *do_early_data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  CURLcode result = CURLE_OK;

  *do_early_data = FALSE;
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA)
  ctx->earlydata_max = scs->earlydata_max;
#endif
#ifdef USE_GNUTLS
  ctx->earlydata_max =
    gnutls_record_get_max_early_data_size(ctx->tls.gtls.session);
#endif /* USE_GNUTLS */
#ifdef USE_WOLFSSL
#ifdef WOLFSSL_EARLY_DATA
  ctx->earlydata_max = scs->earlydata_max;
#else
  ctx->earlydata_max = 0;
#endif /* WOLFSSL_EARLY_DATA */
#endif /* USE_WOLFSSL */
#if defined(USE_GNUTLS) || defined(USE_WOLFSSL) || \
    (defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA))
  if((!ctx->earlydata_max)) {
    CURL_TRC_CF(data, cf, "SSL session does not allow earlydata");
  }
  else if(!Curl_alpn_contains_proto(alpns, scs->alpn)) {
    CURL_TRC_CF(data, cf, "SSL session from different ALPN, no early data");
  }
  else if(!scs->quic_tp || !scs->quic_tp_len) {
    CURL_TRC_CF(data, cf, "no 0RTT transport parameters, no early data, ");
  }
  else {
    int rv;
    rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
      ctx->qconn, (const uint8_t *)scs->quic_tp, scs->quic_tp_len);
    if(rv)
      CURL_TRC_CF(data, cf, "no early data, failed to set 0RTT transport "
                  "parameters: %s", ngtcp2_strerror(rv));
    else {
      infof(data, "SSL session allows %zu bytes of early data, "
            "reusing ALPN '%s'", ctx->earlydata_max, scs->alpn);
      result = cf_ngtcp2_h3conn_init(cf, data);
      if(!result) {
        ctx->use_earlydata = TRUE;
        proxy_ctx->connected = TRUE;
        *do_early_data = TRUE;
      }
    }
  }
#else /* not supported in the TLS backend */
  (void)data;
  (void)ctx;
  (void)scs;
  (void)alpns;
#endif
  return result;
}

static CURLcode cf_h3_proxy_ctx_init(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = NULL;
  int rc;
  int rv;
  CURLcode result = CURLE_OK;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int qfd;
  static const struct alpn_spec ALPN_SPEC_H3 = {{ "h3", "h3-29" }, 2};
  struct proxy_pkt_io_ctx pktx;

  ctx = curlx_calloc(1, sizeof(struct cf_ngtcp2_proxy_ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_ngtcp2_proxy_ctx_init(ctx);

  memset(&proxy_ctx->tunnel, 0, sizeof(proxy_ctx->tunnel));

  Curl_bufq_init2(&proxy_ctx->inbufq, PROXY_H3_STREAM_CHUNK_SIZE,
                  PROXY_H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);

  result = h3_tunnel_stream_init(cf, &proxy_ctx->tunnel);
  if(result)
    goto out;

  DEBUGASSERT(ctx->initialized);
  ctx->started_at = *Curl_pgrs_now(data);

  /* Initialize connection IDs BEFORE creating the connection */
  ctx->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    goto out;

  ctx->scid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->scid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    goto out;

  (void)Curl_qlogdir(data, ctx->scid.data, NGTCP2_MAX_CIDLEN, &qfd);
  ctx->qlogfd = qfd; /* -1 if failure above */

  result = CURLE_QUIC_CONNECT_ERROR;
  if(Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL))
    goto out;
  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                   &ctx->q.local_addrlen);
  if(rv == -1)
    goto out;

  /* Initialize vquic context BEFORE proxy_pktx_init which needs it */
  result = vquic_ctx_init(data, &ctx->q);
  if(result)
    goto out;

  /* Set ngtcp2_ctx in proxy_ctx BEFORE proxy_pktx_init which accesses it */
  proxy_ctx->ngtcp2_ctx = ctx;

  /* Now we can safely initialize pktx and settings */
  proxy_pktx_init(&pktx, cf, data);
  quic_settings_proxy(ctx, data, &pktx);

  ngtcp2_addr_init(&ctx->connected_path.local,
                   (struct sockaddr *)&ctx->q.local_addr,
                   ctx->q.local_addrlen);
  ngtcp2_addr_init(&ctx->connected_path.remote,
                   &sockaddr->curl_sa_addr, (socklen_t)sockaddr->addrlen);

  rc = ngtcp2_conn_client_new(&ctx->qconn, &ctx->dcid, &ctx->scid,
                              &ctx->connected_path,
                              NGTCP2_PROTO_VER_V1, &ngtcp2_proxy_callbacks,
                              &ctx->settings, &ctx->transport_params,
                              Curl_ngtcp2_mem(), cf);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  ctx->conn_ref.get_conn = proxy_get_conn;
  ctx->conn_ref.user_data = cf;

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer, &ALPN_SPEC_H3,
                               cf_ngtcp2_proxy_tls_ctx_setup, &ctx->tls,
                               &ctx->conn_ref,
                               cf_ngtcp2_proxy_on_session_reuse);
  if(result)
    goto out;

#if defined(USE_OPENSSL) && defined(OPENSSL_QUIC_API2)
  if(ngtcp2_crypto_ossl_ctx_new(&ctx->ossl_ctx, ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_ctx_new failed");
    result = CURLE_FAILED_INIT;
    goto out;
  }
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->ossl_ctx);
  if(ngtcp2_crypto_ossl_configure_client_session(ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_configure_client_session failed");
    result = CURLE_FAILED_INIT;
    goto out;
  }
#elif defined(USE_OPENSSL)
  SSL_set_quic_use_legacy_codepoint(ctx->tls.ossl.ssl, 0);
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.ossl.ssl);
#else
#error "ngtcp2 TLS backend not defined"
#endif /* USE_OPENSSL */

  ngtcp2_ccerr_default(&ctx->last_error);

  proxy_ctx->connected = FALSE;

out:
  if(result) {
    if(ctx) {
      proxy_ctx->ngtcp2_ctx = NULL; /* Clear before freeing on error */
      cf_ngtcp2_proxy_ctx_free(ctx);
    }
  }
  CURL_TRC_CF(data, cf, "QUIC tls init -> %d", result);
  return result;
}

static CURLcode h3_submit_CONNECT(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h3_tunnel_stream *ts)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  CURLcode result;
  struct httpreq *req = NULL;

  result = Curl_http_proxy_create_tunnel_request(&req, cf, data,
                                                  PROXY_HTTP_V3,
                                                  (bool)proxy_ctx->udp_tunnel);
  if(result)
    goto out;
  result = Curl_creader_set_null(data);
  if(result)
    goto out;

  proxy_h3_submit(&ts->stream_id, cf, data, req, &result);

out:
  if(req)
    Curl_http_req_free(req);
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  return result;
}

static CURLcode
h3_proxy_inspect_response(struct Curl_cfilter *cf,
                 struct Curl_easy *data,
                 struct h3_tunnel_stream *ts)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  proxy_inspect_result res;
  CURLcode result;

  result = Curl_http_proxy_inspect_tunnel_response(
      cf, data, ts->resp, (bool)proxy_ctx->udp_tunnel, &res);
  if(result)
    return result;
  switch(res) {
  case PROXY_INSPECT_OK:
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data,
                       (bool)proxy_ctx->udp_tunnel);
    break;
  case PROXY_INSPECT_FAILED:
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data,
                       (bool)proxy_ctx->udp_tunnel);
    result = CURLE_COULDNT_CONNECT;
    break;
  case PROXY_INSPECT_AUTH_RETRY:
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_INIT, data,
                       (bool)proxy_ctx->udp_tunnel);
    break;
  }
  return result;
}

static CURLcode cf_h3_proxy_quic_connect(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;
  struct proxy_pkt_io_ctx pktx;

  if(proxy_ctx->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(cf->next->cft == &Curl_cft_udp) {
    /* Connect the UDP filter first */
    if(!cf->next->connected) {
      result = Curl_conn_cf_connect(cf->next, data, done);
      if(result || !*done)
        return result;
    }
  }

  *done = FALSE;

  if(!proxy_ctx->ngtcp2_ctx) {
    result = cf_h3_proxy_ctx_init(cf, data);
    if(result)
      return result;
  }

  /* Initialize pktx AFTER ensuring ngtcp2_ctx exists */
  proxy_pktx_init(&pktx, cf, data);

  CF_DATA_SAVE(save, cf, data);

  if(!proxy_ctx->ngtcp2_ctx->qconn) {
    proxy_ctx->ngtcp2_ctx->started_at = *Curl_pgrs_now(data);
    if(proxy_ctx->connected) {
      *done = TRUE;
      goto out;
    }
    result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = proxy_h3_progress_ingress_ngtcp2(cf, data, &pktx);
  if(result)
    goto out;

  result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
  if(result)
    goto out;

  if(ngtcp2_conn_get_handshake_completed(proxy_ctx->ngtcp2_ctx->qconn)) {
    result = proxy_ctx->ngtcp2_ctx->tls_vrfy_result;
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      proxy_ctx->connected = TRUE;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }

out:
  if(proxy_ctx->ngtcp2_ctx->qconn &&
     ((result == CURLE_RECV_ERROR) || (result == CURLE_SEND_ERROR)) &&
     ngtcp2_conn_in_draining_period(proxy_ctx->ngtcp2_ctx->qconn)) {
    const ngtcp2_ccerr *cerr =
      ngtcp2_conn_get_ccerr(proxy_ctx->ngtcp2_ctx->qconn);

    result = CURLE_COULDNT_CONNECT;
    if(cerr) {
      CURL_TRC_CF(data, cf, "connect error, type=%d, code=%"
                  PRIu64,
                  cerr->type, (uint64_t)cerr->error_code);
      switch(cerr->type) {
      case NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION:
        CURL_TRC_CF(data, cf, "error in version negotiation");
        break;
      default:
        if(cerr->error_code >= NGTCP2_CRYPTO_ERROR) {
          CURL_TRC_CF(data, cf, "crypto error, tls alert=%u",
                      (unsigned int)(cerr->error_code & 0xffU));
        }
        else if(cerr->error_code == NGTCP2_CONNECTION_REFUSED) {
          CURL_TRC_CF(data, cf, "connection refused by server");
          /* When a QUIC server instance is shutting down, it may send us a
           * CONNECTION_CLOSE with this code right away. We want
           * to keep on trying in this case. */
          result = CURLE_WEIRD_SERVER_REPLY;
        }
      }
    }
  }

#ifdef CURLVERBOSE
  if(result) {
    if(cf->next->cft == &Curl_cft_udp) {
      struct ip_quadruple ip;

      if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
        infof(data, "QUIC connect to %s port %u failed: %s",
              ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
    }
  }
#endif
  if(!result && proxy_ctx->ngtcp2_ctx->qconn) {
    result = check_and_set_expiry_ngtcp2(cf, data, &pktx);
  }
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode H3_CONNECT(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct h3_tunnel_stream *ts)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(ts);
  DEBUGASSERT(ts->authority);

  do {
    switch(ts->state) {
    case H3_TUNNEL_INIT:
      CURL_TRC_CF(data, cf, "[0] CONNECT start for %s", ts->authority);
      result = h3_submit_CONNECT(cf, data, ts);
      if(result)
        goto out;
      h3_tunnel_go_state(cf, ts, H3_TUNNEL_CONNECT, data,
                         (bool)ctx->udp_tunnel);

      result = proxy_h3_progress_egress_ngtcp2(cf, data, NULL);
      if(result)
        goto out;
      FALLTHROUGH();

    case H3_TUNNEL_CONNECT:
      /* Non-blocking: call ingress/egress once and return.
       * The multi interface will call us again when ready. */
      result = proxy_h3_progress_ingress_ngtcp2(cf, data, NULL);
      if(result)
        goto out;
      result = proxy_h3_progress_egress_ngtcp2(cf, data, NULL);
      if(result && result != CURLE_AGAIN) {
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data,
                           (bool)ctx->udp_tunnel);
        goto out;
      }

      if(ts->has_final_response) {
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_RESPONSE, data,
                           (bool)ctx->udp_tunnel);
      }
      else {
        /* Not done yet, return and let multi interface call us again */
        result = CURLE_OK;
        goto out;
      }
      FALLTHROUGH();

    case H3_TUNNEL_RESPONSE:
      DEBUGASSERT(ts->has_final_response);
      result = h3_proxy_inspect_response(cf, data, ts);
      if(result)
        goto out;
      ctx->connected = TRUE;
      break;

    case H3_TUNNEL_ESTABLISHED:
      return CURLE_OK;

    case H3_TUNNEL_FAILED:
      return CURLE_RECV_ERROR;

    default:
      break;
    }

  } while(ts->state == H3_TUNNEL_INIT);

out:
  if((result && (result != CURLE_AGAIN)) || ctx->tunnel.closed)
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data, (bool)ctx->udp_tunnel);
  return result;
}

static CURLcode
cf_h3_proxy_connect(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save = {0};
  CURLcode result = CURLE_OK;
  timediff_t check;
  struct h3_tunnel_stream *ts = &proxy_ctx->tunnel;
  bool data_saved = FALSE;

  /* Curl_cft_http_proxy --> Curl_cft_h3_proxy --> Curl_cft_udp */
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;

  check = Curl_timeleft_ms(data);
  if(check <= 0) {
    failf(data, "Proxy CONNECT aborted due to timeout");
    result = CURLE_OPERATION_TIMEDOUT;
    goto out;
  }

  result = cf_h3_proxy_quic_connect(cf, data, done);
  if(*done != TRUE)
    goto out;

  CF_DATA_SAVE(save, cf, data);
  data_saved = TRUE;

  /* At this point the QUIC is connected, but the proxy isn't connected */
  *done = FALSE;

  result = H3_CONNECT(cf, data, ts);

out:
  *done = (result == CURLE_OK) && (ts->state == H3_TUNNEL_ESTABLISHED);
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

static CURLcode h3_proxy_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  (void)cf;
  if(!pause) {
    /* unpaused. make it run again right away */
    Curl_multi_mark_dirty(data);
  }
  return CURLE_OK;
}

static void h3_proxy_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream;
  (void)cf;
  if(!ctx)
    return;

  stream = H3_PROXY_STREAM_CTX(ctx, data);
  if(stream) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] easy handle is done",
                stream->id);
    cf_ngtcp2_proxy_stream_close(cf, data, stream);
    Curl_uint32_hash_remove(&ctx->streams, data->mid);
    if(!Curl_uint32_hash_count(&ctx->streams))
      cf_ngtcp2_proxy_setup_keep_alive(cf, data);
  }
}

static CURLcode cf_h3_proxy_cntrl(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  int event, int arg1, void *arg2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_proxy_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_proxy_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct cf_ngtcp2_proxy_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    struct h3_proxy_stream_ctx *stream = NULL;
    if(ctx) {
      stream = H3_PROXY_STREAM_CTX(ctx, data);
      if(stream && !stream->send_closed &&
         (H3_STREAM_ID(stream) != proxy_ctx->tunnel.stream_id)) {
        stream->send_closed = TRUE;
        stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
          stream->sendbuf_len_in_flight;
        (void)nghttp3_conn_resume_stream(ctx->h3conn, H3_STREAM_ID(stream));
      }
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

static void cf_h3_proxy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    /* Clean up the ngtcp2 context properly */
    if(ctx->ngtcp2_ctx) {
      CURL_TRC_CF(data, cf, "cf_ngtcp2_proxy_ctx_close()");
      cf_ngtcp2_proxy_close(cf, data);
      cf_ngtcp2_proxy_ctx_free(ctx->ngtcp2_ctx);
      ctx->ngtcp2_ctx = NULL;
    }
    cf_h3_proxy_ctx_free(ctx);
    cf->ctx = NULL;
  }
}

static void cf_h3_proxy_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  if(ctx) {
    if(ctx->ngtcp2_ctx) {
      cf_ngtcp2_proxy_close(cf, data);
      cf_ngtcp2_proxy_ctx_free(ctx->ngtcp2_ctx);
      ctx->ngtcp2_ctx = NULL;
    }
    cf_h3_proxy_ctx_clear(ctx);
    cf->connected = FALSE;
  }

  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}

static CURLcode cf_h3_proxy_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data, bool *done)
{
  return cf_ngtcp2_proxy_shutdown(cf, data, done);
}

struct Curl_cftype Curl_cft_h3_proxy = {
    "H3-PROXY",
    CF_TYPE_IP_CONNECT | CF_TYPE_PROXY,
    CURL_LOG_LVL_NONE,
    cf_h3_proxy_destroy,
    cf_h3_proxy_connect,
    cf_h3_proxy_close,
    cf_h3_proxy_shutdown,
    cf_h3_proxy_adjust_pollset,
    cf_h3_proxy_data_pending,
    cf_h3_proxy_send,
    cf_h3_proxy_recv,
    cf_h3_proxy_cntrl,
    cf_h3_proxy_is_alive,
    Curl_cf_def_conn_keep_alive,
    cf_h3_proxy_query,
};

static int Curl_get_QUIC_addr_info(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct Curl_sockaddr_ex *addr)
{
  const struct Curl_addrinfo *ai;

  ai = Curl_conn_dns_get_ip_addr(data, cf->sockindex, cf->conn->ip_version);
  if(!ai)
    return 0; /* no address found */

  return (Curl_socket_addr_from_ai(addr, ai, TRNSPRT_QUIC) == CURLE_OK);
}

CURLcode Curl_cf_h3_proxy_insert_after(struct Curl_cfilter **pcf,
                                       struct Curl_easy *data,
                                       bool udp_tunnel)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_h3_proxy_ctx *ctx;
  struct connectdata *conn = data->conn;
  struct Curl_sockaddr_ex addr = {0};
  CURLcode result = CURLE_OUT_OF_MEMORY;
  int rv;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;
  ctx->udp_tunnel = udp_tunnel;

  result = Curl_cf_create(&cf, &Curl_cft_h3_proxy, ctx);
  if(result)
    goto out;

  rv = Curl_get_QUIC_addr_info(*pcf, data, &addr);
  if(!rv) {
    failf(data, "Failed to get QUIC UDP socket addr info");
    result = CURLE_COULDNT_RESOLVE_HOST;
    goto out;
  }

  result = Curl_cf_udp_create(&cf->next, data, conn, &addr, TRNSPRT_QUIC);
  if(result)
    goto out;

  Curl_conn_cf_insert_after(*pcf, cf);

out:
  if(result) {
    if(cf)
      Curl_conn_cf_discard_chain(&cf, data);
    else if(ctx)
      cf_h3_proxy_ctx_free(ctx);
  }
  return result;
}

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_PROXY && USE_NGHTTP3 && \
                USE_NGTCP2 && USE_OPENSSL */

/* Restore the default CF_CTX_CALL_DATA for subsequent files in unity builds */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf) \
  ((struct ssl_connect_data *)(cf)->ctx)->call_data
