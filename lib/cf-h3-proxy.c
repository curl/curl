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
    defined(USE_NGHTTP3) && !defined(CURL_DISABLE_PROXY)

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <nghttp3/nghttp3.h>

#include "urldata.h"
#include "hash.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "multiif.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "strerror.h"
#include "bufq.h"
#include "curlx/dynbuf.h"
#include "dynhds.h"
#include "http1.h"
#include "http_proxy.h"
#include "select.h"
#include "uint-hash.h"
#include "vquic/vquic.h"
#include "vquic/vquic_int.h"
#include "vquic/vquic-tls.h"
#include "vtls/keylog.h"
#include "vtls/vtls.h"
#include "vtls/openssl.h"
#include "curl_trc.h"
#include "cf-h3-proxy.h"
#include "url.h"
#include "curlx/warnless.h"
#include "capsule.h"

/* might not need line nos 63-350 */

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE) / 2

#define PROXY_H3_STREAM_RECV_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)
#define PROXY_H3_STREAM_SEND_CHUNKS 1

#define H3_TUNNEL_RECV_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)
#define H3_TUNNEL_SEND_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
typedef uint32_t sslerr_t;
#else
typedef unsigned long sslerr_t;
#endif

static const char *osslq_SSL_ERROR_to_str(int err)
{
  switch(err) {
  case SSL_ERROR_NONE:
    return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:
    return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:
    return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:
    return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:
    return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:
    return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:
    return "SSL_ERROR_WANT_ACCEPT";
#ifdef SSL_ERROR_WANT_ASYNC
  case SSL_ERROR_WANT_ASYNC:
    return "SSL_ERROR_WANT_ASYNC";
#endif
#ifdef SSL_ERROR_WANT_ASYNC_JOB
  case SSL_ERROR_WANT_ASYNC_JOB:
    return "SSL_ERROR_WANT_ASYNC_JOB";
#endif
#ifdef SSL_ERROR_WANT_EARLY
  case SSL_ERROR_WANT_EARLY:
    return "SSL_ERROR_WANT_EARLY";
#endif
  default:
    return "SSL_ERROR unknown";
  }
}

/* Return error string for last OpenSSL error */
static char *osslq_strerror(unsigned long error, char *buf, size_t size)
{
  DEBUGASSERT(size);
  *buf = '\0';

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
  ERR_error_string_n((uint32_t)error, buf, size);
#else
  ERR_error_string_n(error, buf, size);
#endif

  if(!*buf) {
    const char *msg = error ? "Unknown error" : "No error";
    if(strlen(msg) < size)
      strcpy(buf, msg);
  }

  return buf;
}

static CURLcode make_bio_addr(BIO_ADDR **pbio_addr,
                              const struct Curl_sockaddr_ex *addr)
{
  BIO_ADDR *ba;
  CURLcode result = CURLE_FAILED_INIT;

  ba = BIO_ADDR_new();
  if(!ba) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  switch(addr->family) {
  case AF_INET:
  {
    const struct sockaddr_in *const sin =
        (const struct sockaddr_in *)&addr->curl_sa_addr;
    if(!BIO_ADDR_rawmake(ba, AF_INET, &sin->sin_addr,
                          sizeof(sin->sin_addr), sin->sin_port)) {
      goto out;
    }
    result = CURLE_OK;
    break;
  }
#ifdef USE_IPV6
  case AF_INET6:
  {
    const struct sockaddr_in6 *const sin =
        (const struct sockaddr_in6 *)&addr->curl_sa_addr;
    if(!BIO_ADDR_rawmake(ba, AF_INET6, &sin->sin6_addr,
                          sizeof(sin->sin6_addr), sin->sin6_port)) {
    }
    result = CURLE_OK;
    break;
  }
#endif /* USE_IPV6 */
  default:
    /* sunsupported */
    DEBUGASSERT(0);
    break;
  }

out:
  if(result && ba) {
    BIO_ADDR_free(ba);
    ba = NULL;
  }
  *pbio_addr = ba;
  return result;
}

typedef enum
{
  H3_TUNNEL_INIT,     /* init/default/no tunnel state */
  H3_TUNNEL_CONNECT,  /* CONNECT request is being sent */
  H3_TUNNEL_RESPONSE, /* CONNECT response received completely */
  H3_TUNNEL_ESTABLISHED,
  H3_TUNNEL_FAILED
} h3_tunnel_state;

struct tunnel_stream
{
  struct http_resp *resp;
  char *authority;
  curl_int64_t stream_id;
  h3_tunnel_state state;
  BIT(has_final_response);
  BIT(closed);
};

static CURLcode tunnel_stream_init(struct Curl_cfilter *cf,
                                   struct tunnel_stream *ts)
{
  const char *hostname;
  int port;
  bool ipv6_ip;
  CURLcode result;

  ts->state = H3_TUNNEL_INIT;
  ts->stream_id = -1;
  ts->has_final_response = FALSE;

  result = Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip);
  if(result)
    return result;

  ts->authority = /* host:port with IPv6 support */
      aprintf("%s%s%s:%d", ipv6_ip ? "[" : "", hostname,
              ipv6_ip ? "]" : "", port);
  if(!ts->authority)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static void tunnel_stream_clear(struct tunnel_stream *ts)
{
  Curl_http_resp_free(ts->resp);
  Curl_safefree(ts->authority);
  memset(ts, 0, sizeof(*ts));
  ts->state = H3_TUNNEL_INIT;
}

static void h3_tunnel_go_state(struct Curl_cfilter *cf,
                               struct tunnel_stream *ts,
                               h3_tunnel_state new_state,
                               struct Curl_easy *data)
{
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
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'init'",
                ts->stream_id);
    tunnel_stream_clear(ts);
    break;

  case H3_TUNNEL_CONNECT:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'connect'",
                ts->stream_id);
    ts->state = H3_TUNNEL_CONNECT;
    break;

  case H3_TUNNEL_RESPONSE:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'response'",
                ts->stream_id);
    ts->state = H3_TUNNEL_RESPONSE;
    break;

  case H3_TUNNEL_ESTABLISHED:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'established'",
                ts->stream_id);
    if(cf->conn->bits.udp_tunnel_proxy) {
      infof(data, "CONNECT-UDP phase completed for HTTP/3 proxy");
    }
    else {
      infof(data, "CONNECT phase completed for HTTP/3 proxy");
    }
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    FALLTHROUGH();
  case H3_TUNNEL_FAILED:
    if(new_state == H3_TUNNEL_FAILED)
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'failed'",
                  ts->stream_id);
    ts->state = new_state;
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it is not accidentally used for the document request
       after we have connected. So let's free and clear it here. */
    Curl_safefree(data->state.aptr.proxyuserpwd);
    break;
  }
}

/* QUIC stream (not necessarily H3) */
struct cf_osslq_stream {
  curl_int64_t id;
  SSL *ssl;
  struct bufq recvbuf; /* QUIC war data recv buffer */
  BIT(recvd_eos);
  BIT(closed);
  BIT(reset);
  BIT(send_blocked);
  BIT(tunnel_stream);
};

static CURLcode cf_osslq_stream_open(struct cf_osslq_stream *s,
                                     SSL *conn,
                                     uint64_t flags,
                                     struct bufc_pool *bufcp,
                                     void *user_data)
{
  DEBUGASSERT(!s->ssl);
  Curl_bufq_initp(&s->recvbuf, bufcp, 1, BUFQ_OPT_NONE);
  s->ssl = SSL_new_stream(conn, flags);
  if(!s->ssl) {
    return CURLE_FAILED_INIT;
  }
  s->id = (curl_int64_t)SSL_get_stream_id(s->ssl);
  SSL_set_app_data(s->ssl, user_data);
  return CURLE_OK;
}

static void cf_osslq_stream_cleanup(struct cf_osslq_stream *s)
{
  if(s->ssl) {
    SSL_set_app_data(s->ssl, NULL);
    SSL_free(s->ssl);
  }
  Curl_bufq_free(&s->recvbuf);
  memset(s, 0, sizeof(*s));
}

static void cf_osslq_stream_close(struct cf_osslq_stream *s)
{
  if(s->ssl) {
    SSL_free(s->ssl);
    s->ssl = NULL;
  }
}

struct cf_osslq_h3conn {
  nghttp3_conn *conn;
  nghttp3_settings settings;
  struct cf_osslq_stream s_ctrl;
  struct cf_osslq_stream s_qpack_enc;
  struct cf_osslq_stream s_qpack_dec;
  struct cf_osslq_stream remote_ctrl[3]; /* uni streams opened by the peer */
  size_t remote_ctrl_n; /* number of peer streams opened */
};

static void cf_osslq_h3conn_cleanup(struct cf_osslq_h3conn *h3)
{
  size_t i;

  if(h3->conn)
    nghttp3_conn_del(h3->conn);
  cf_osslq_stream_cleanup(&h3->s_ctrl);
  cf_osslq_stream_cleanup(&h3->s_qpack_enc);
  cf_osslq_stream_cleanup(&h3->s_qpack_dec);
  for(i = 0; i < h3->remote_ctrl_n; ++i) {
    cf_osslq_stream_cleanup(&h3->remote_ctrl[i]);
  }
}

struct cf_osslq_ctx
{
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
  struct cf_osslq_h3conn h3;
  struct curltime started_at;    /* time the current attempt started */
  struct curltime handshake_at;  /* time connect handshake finished */
  struct curltime first_byte_at; /* when first byte was recvd */
  struct bufc_pool stream_bufcp; /* chunk pool for streams */
  struct uint_hash streams;
                           /* hash `data->mid` to `h3_proxy_stream_ctx` */
  size_t max_stream_window;      /* max flow window for one stream */
  uint64_t max_idle_ms;          /* max idle time for QUIC connection */
  SSL_POLL_ITEM *poll_items;     /* Array for polling on writable state */
  struct Curl_easy **curl_items; /* Array of easy objs */
  size_t items_max;              /* max elements in poll/curl_items */
  struct Curl_addrinfo *addr;    /* remote addr */
  BIT(initialized);
  BIT(got_first_byte);    /* if first byte was received */
  BIT(x509_store_setup);  /* if x509 store has been set up */
  BIT(protocol_shutdown); /* QUIC connection is shut down */
  BIT(need_recv);         /* QUIC connection needs to receive */
  BIT(need_send);         /* QUIC connection needs to send */
};

static void h3_stream_hash_free(unsigned int id, void *stream);

static void cf_osslq_ctx_init(struct cf_osslq_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  Curl_bufcp_init(&ctx->stream_bufcp, PROXY_H3_STREAM_CHUNK_SIZE,
                  PROXY_H3_STREAM_POOL_SPARES);
  Curl_uint_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->poll_items = NULL;
  ctx->curl_items = NULL;
  ctx->items_max = 0;
  ctx->initialized = TRUE;
}

static void cf_osslq_ctx_free(struct cf_osslq_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_bufcp_free(&ctx->stream_bufcp);
    Curl_uint_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
    free(ctx->poll_items);
    free(ctx->curl_items);
  }
  free(ctx);
}

static void cf_osslq_ctx_close(struct cf_osslq_ctx *ctx)
{
  cf_osslq_h3conn_cleanup(&ctx->h3);
  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
}

struct cf_h3_proxy_ctx
{
  struct cf_osslq_ctx *osslq_ctx;
  struct bufq inbufq;          /* network receive buffer */
  struct tunnel_stream tunnel; /* our tunnel CONNECT stream */
  int32_t goaway_error;
  BIT(partial_read);
  BIT(connected);
};

static CURLcode cf_h3_proxy_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data, bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;
  int rc;

  if(!cf->connected || !ctx->h3.conn || cf->shutdown ||
                                        ctx->protocol_shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  ctx->need_send = FALSE;
  ctx->need_recv = FALSE;

  rc = SSL_shutdown_ex(ctx->tls.ossl.ssl,
                       SSL_SHUTDOWN_FLAG_NO_BLOCK, NULL, 0);
  if(rc == 0) { /* ongoing */
    CURL_TRC_CF(data, cf, "shutdown ongoing");
    ctx->need_recv = TRUE;
    goto out;
  }
  else if(rc == 1) { /* done */
    CURL_TRC_CF(data, cf, "shutdown finished");
    *done = TRUE;
    goto out;
  }
  else {
    long sslerr;
    char err_buffer[256];
    int err = SSL_get_error(ctx->tls.ossl.ssl, rc);

    switch(err) {
    case SSL_ERROR_NONE:
    case SSL_ERROR_ZERO_RETURN:
      CURL_TRC_CF(data, cf, "shutdown not received, but closed");
      *done = TRUE;
      goto out;
    case SSL_ERROR_WANT_READ:
      /* SSL has send its notify and now wants to read the reply
       * from the server. We are not really interested in that. */
      CURL_TRC_CF(data, cf, "shutdown sent, want receive");
      ctx->need_recv = TRUE;
      goto out;
    case SSL_ERROR_WANT_WRITE:
      CURL_TRC_CF(data, cf, "shutdown send blocked");
      ctx->need_send = TRUE;
      goto out;
    default:
      /* We give up on this. */
      sslerr = ERR_get_error();
      CURL_TRC_CF(data, cf, "shutdown, ignore recv error: '%s', errno %d",
                  (sslerr ?
                    osslq_strerror(sslerr, err_buffer, sizeof(err_buffer)) :
                    osslq_SSL_ERROR_to_str(err)),
                  SOCKERRNO);
      *done = TRUE;
      result = CURLE_OK;
      goto out;
    }
  }
out:
  return result;
}

static void cf_h3_proxy_ctx_clear(struct cf_h3_proxy_ctx *ctx)
{
  Curl_bufq_free(&ctx->inbufq);
  tunnel_stream_clear(&ctx->tunnel);
  memset(ctx, 0, sizeof(*ctx));
}

static void cf_h3_proxy_ctx_free(struct cf_h3_proxy_ctx *ctx)
{
  if(ctx) {
    cf_h3_proxy_ctx_clear(ctx);
    free(ctx);
  }
}

static CURLcode cf_osslq_h3conn_add_stream(struct cf_osslq_h3conn *h3,
                                           SSL *stream_ssl,
                                           struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  curl_int64_t stream_id = (curl_int64_t)SSL_get_stream_id(stream_ssl);

  if(h3->remote_ctrl_n >= ARRAYSIZE(h3->remote_ctrl)) {
    /* rejected, we are full */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] rejecting remote stream",
                stream_id);
    SSL_free(stream_ssl);
    return CURLE_FAILED_INIT;
  }
  switch(SSL_get_stream_type(stream_ssl)) {
  case SSL_STREAM_TYPE_READ:{
    struct cf_osslq_stream *nstream = &h3->remote_ctrl[h3->remote_ctrl_n++];
    nstream->id = stream_id;
    nstream->ssl = stream_ssl;
    Curl_bufq_initp(&nstream->recvbuf, &ctx->stream_bufcp, 1, BUFQ_OPT_NONE);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] accepted remote uni stream",
                stream_id);
    break;
  }
  default:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reject remote non-uni-read"
                          " stream",
                stream_id);
    SSL_free(stream_ssl);
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static CURLcode cf_osslq_ssl_err(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 int detail, CURLcode def_result)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = def_result;
  sslerr_t errdetail;
  char ebuf[256] = "unknown";
  const char *err_descr = ebuf;
  long lerr;
  int lib;
  int reason;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

  errdetail = ERR_get_error();
  lib = ERR_GET_LIB(errdetail);
  reason = ERR_GET_REASON(errdetail);

  if((lib == ERR_LIB_SSL) &&
      ((reason == SSL_R_CERTIFICATE_VERIFY_FAILED) ||
       (reason == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED))) {
    result = CURLE_PEER_FAILED_VERIFICATION;

    lerr = SSL_get_verify_result(ctx->tls.ossl.ssl);
    if(lerr != X509_V_OK) {
      ssl_config->certverifyresult = lerr;
      msnprintf(ebuf, sizeof(ebuf),
                "SSL certificate problem: %s",
                X509_verify_cert_error_string(lerr));
    }
    else
      err_descr = "SSL certificate verification failed";
  }
#ifdef SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
  /* SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED is only available on
     OpenSSL version above v1.1.1, not LibreSSL, BoringSSL, or AWS-LC */
  else if((lib == ERR_LIB_SSL) &&
           (reason == SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED)) {
    /* If client certificate is required, communicate the
       error to client */
    result = CURLE_SSL_CLIENTCERT;
    osslq_strerror(errdetail, ebuf, sizeof(ebuf));
  }
#endif
  else if((lib == ERR_LIB_SSL) && (reason == SSL_R_PROTOCOL_IS_SHUTDOWN)) {
    ctx->protocol_shutdown = TRUE;
    err_descr = "QUIC connection has been shut down";
    result = def_result;
  }
  else {
    result = def_result;
    osslq_strerror(errdetail, ebuf, sizeof(ebuf));
  }

  /* detail is already set to the SSL error above */

  /* If we e.g. use SSLv2 request-method and the server does not like us
   * (RST connection, etc.), OpenSSL gives no explanation whatsoever and
   * the SO_ERROR is also lost.
   */
  if(CURLE_SSL_CONNECT_ERROR == result && errdetail == 0) {
    char extramsg[80] = "";
    int sockerr = SOCKERRNO;
    struct ip_quadruple ip;

    Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
    if(sockerr && detail == SSL_ERROR_SYSCALL)
      Curl_strerror(sockerr, extramsg, sizeof(extramsg));
    failf(data, "QUIC connect: %s in connection to %s:%d (%s)",
          extramsg[0] ? extramsg : osslq_SSL_ERROR_to_str(detail),
          ctx->peer.dispname, ip.remote_port, ip.remote_ip);
  }
  else {
    /* Could be a CERT problem */
    failf(data, "%s", err_descr);
  }
  return result;
}

static CURLcode cf_osslq_verify_peer(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */

  return Curl_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}

/**
 * All about the H3 internals of a stream
 */
struct h3_proxy_stream_ctx
{
  struct cf_osslq_stream s;
  struct bufq sendbuf;          /* h3 request body */
  struct bufq recvbuf;          /* h3 response body */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  curl_uint64_t error3;         /* HTTP/3 stream error code */
  curl_off_t upload_left;       /* number of request bytes left to upload */
  curl_off_t tun_data_recvd;    /* number of bytes received over tunnel */
  int status_code;              /* HTTP status code */
  bool resp_hds_complete;       /* we have a complete, final response */
  bool closed;                  /* TRUE on stream close */
  bool reset;                   /* TRUE on stream reset */
  bool send_closed;             /* stream is local closed */
};

#define H3_PROXY_STREAM_CTX(ctx,data)                                     \
  (data ? Curl_uint_hash_get(&(ctx)->streams, (data)->mid) : NULL)

static void h3_stream_ctx_free(struct h3_proxy_stream_ctx *stream)
{
  cf_osslq_stream_cleanup(&stream->s);
  Curl_bufq_free(&stream->sendbuf);
  Curl_bufq_free(&stream->recvbuf);
  free(stream);
}

static void h3_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct h3_proxy_stream_ctx *)stream);
}

static CURLcode h3_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

  if(!data)
    return CURLE_FAILED_INIT;

  if(stream)
    return CURLE_OK;

  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->s.id = -1;
  /* on send, we control how much we put into the buffer */
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  PROXY_H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  stream->sendbuf_len_in_flight = 0;
  /* on recv, we need a flexible buffer limit since we also write
   * headers to it that are not counted against the nghttp3 flow limits. */
  Curl_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                  PROXY_H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);

  if(!Curl_uint_hash_set(&ctx->streams, data->mid, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

struct cf_ossq_find_ctx {
  curl_int64_t stream_id;
  struct h3_proxy_stream_ctx *stream;
};

static bool cf_osslq_find_stream(unsigned int mid, void *val, void *user_data)
{
  struct h3_proxy_stream_ctx *stream = val;
  struct cf_ossq_find_ctx *fctx = user_data;

  (void)mid;
  if(stream && stream->s.id == fctx->stream_id) {
    fctx->stream = stream;
    return FALSE; /* stop iterating */
  }
  return TRUE;
}

static struct cf_osslq_stream *cf_osslq_get_qstream(struct Curl_cfilter *cf,
                                                    struct Curl_easy *data,
                                                    int64_t stream_id)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

  if(stream && stream->s.id == stream_id) {
    return &stream->s;
  }
  else if(ctx->h3.s_ctrl.id == stream_id) {
    return &ctx->h3.s_ctrl;
  }
  else if(ctx->h3.s_qpack_enc.id == stream_id) {
    return &ctx->h3.s_qpack_enc;
  }
  else if(ctx->h3.s_qpack_dec.id == stream_id) {
    return &ctx->h3.s_qpack_dec;
  }
  else {
    struct cf_ossq_find_ctx fctx;
    fctx.stream_id = stream_id;
    fctx.stream = NULL;
    Curl_uint_hash_visit(&ctx->streams, cf_osslq_find_stream, &fctx);
    if(fctx.stream)
      return &fctx.stream->s;
  }
  return NULL;
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
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
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] RESET: error %" FMT_PRIu64,
                stream->s.id, stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] CLOSED", stream->s.id);
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

#define TMP_BUF_SIZE (size_t) 32768
static size_t head = 0;
static size_t tail = 0;
static char tmp_buf[TMP_BUF_SIZE] = {0};

static int handle_buffered_data(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  size_t nwritten;
  size_t data_len;
  CURLcode result = CURLE_OK;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  data_len = tail - head;

  result = Curl_bufq_write(&proxy_ctx->inbufq,
                           (const unsigned char *)(tmp_buf + head),
                           data_len, &nwritten);
  if(result)
    return 0;

  if(nwritten < data_len) {
    head += nwritten;
    data_len = tail - head + 1;
  }
  else {
    proxy_ctx->partial_read = FALSE;
    head = 0;
    tail = 0;
    memset(tmp_buf, 0, TMP_BUF_SIZE);
  }
  return 0;
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t buflen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  size_t nwritten;
  CURLcode result = CURLE_OK;

  (void)conn;
  (void)stream3_id;

  if(!stream) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  stream->tun_data_recvd += (curl_off_t)buflen;
  CURL_TRC_CF(data, cf, "[cb_h3_recv_data] "
              "[%" FMT_PRId64 "] DATA len=%zu, total=%zd",
              stream->s.id, buflen, stream->tun_data_recvd);

  if(proxy_ctx->partial_read) {
    memcpy(tmp_buf + tail, buf, buflen);
    tail += buflen;
    return 0;
  }

  result = Curl_bufq_write(&proxy_ctx->inbufq, buf, buflen, &nwritten);
  if(result) {
    proxy_ctx->partial_read = TRUE;
    memcpy(tmp_buf + tail, buf, buflen);
    tail += buflen;
    return 0;
  }
  if(nwritten < buflen) {
    proxy_ctx->partial_read = TRUE;
    memcpy(tmp_buf + tail, buf + nwritten, (buflen - nwritten));
    tail += (buflen - nwritten);
    return 0;
  }

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

  (void)conn;
  (void)stream_id;
  if(stream)
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] deferred consume %zu bytes",
                stream->s.id, consumed);
  return 0;
}

static int cb_h3_recv_header(nghttp3_conn *conn, int64_t sid,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  curl_int64_t stream_id = sid;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;
  int http_status;
  struct http_resp *resp;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)cf;

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
    http_status = stream->status_code;
    result = Curl_http_resp_make(&resp, http_status, NULL);
    if(result)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    resp->prev = proxy_ctx->tunnel.resp;
    proxy_ctx->tunnel.resp = resp;
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] header: %.*s: %.*s",
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

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t sid,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)cf;

  if(!stream)
    return 0;

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] end_headers, status=%d",
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

static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  (void)conn;
  (void)app_error_code;

  if(!stream || !stream->s.ssl)
    return 0;

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] stop_sending", stream_id);
  cf_osslq_stream_close(&stream->s);
  return 0;
}

static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  int rv;
  (void)conn;

  if(stream && stream->s.ssl) {
    SSL_STREAM_RESET_ARGS args = {0};
    args.quic_error_code = app_error_code;
    rv = !SSL_stream_reset(stream->s.ssl, &args, sizeof(args));
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
    if(!rv) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
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
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  size_t nwritten = 0;
  size_t nvecs = 0;
  const unsigned char *buf_base;
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

  if(nwritten > 0 && stream->upload_left != -1)
    stream->upload_left -= nwritten;

  /* When we stopped sending and everything in `sendbuf` is "in flight",
   * we are at the end of the request body. */
  /* We should NOT set send_closed = TRUE for tunnel stream */
  if(stream->upload_left == 0 && !stream->s.tunnel_stream) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }

  else if(!nwritten) {
    /* Not EOF, and nothing to give, we signal WOULDBLOCK. */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> AGAIN",
                stream->s.id);
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> "
              "%d vecs%s with %zu (buffered=%zu, left=%" FMT_OFF_T ")",
              stream->s.id, (int)nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf),
              stream->upload_left);
  return (nghttp3_ssize)nvecs;
}

static int cb_h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                                   uint64_t datalen, void *user_data,
                                   void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
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

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_stream_data,
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
  NULL, /* recv_settings */
#ifdef NGHTTP3_CALLBACKS_V2
  NULL, /* recv_origin */
  NULL, /* end_origin */
  NULL, /* rand */
#endif
};

static CURLcode cf_osslq_h3conn_init(struct cf_osslq_ctx *ctx, SSL *conn,
                                     void *user_data)
{
  struct cf_osslq_h3conn *h3 = &ctx->h3;
  CURLcode result;
  int rc;

  nghttp3_settings_default(&h3->settings);
  h3->settings.enable_connect_protocol = 1;
  h3->settings.qpack_max_dtable_capacity = 4096;
  h3->settings.qpack_blocked_streams = 100;
  rc = nghttp3_conn_client_new(&h3->conn,
                               &ngh3_callbacks,
                               &h3->settings,
                               Curl_nghttp3_mem(),
                               user_data);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = cf_osslq_stream_open(&h3->s_ctrl, conn,
                                SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  result = cf_osslq_stream_open(&h3->s_qpack_enc, conn,
                                SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  result = cf_osslq_stream_open(&h3->s_qpack_dec, conn,
                                SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  rc = nghttp3_conn_bind_control_stream(h3->conn, h3->s_ctrl.id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  rc = nghttp3_conn_bind_qpack_streams(h3->conn, h3->s_qpack_enc.id,
                                       h3->s_qpack_dec.id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  result = CURLE_OK;
out:
  return result;
}

struct h3_quic_recv_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct cf_osslq_stream *s;
};

static CURLcode h3_quic_recv(void *reader_ctx,
                            unsigned char *buf, size_t len,
                            size_t *pnread)
{
  struct h3_quic_recv_ctx *x = reader_ctx;
  int rv;

  rv = SSL_read_ex(x->s->ssl, buf, len, pnread);
  if(rv <= 0) {
    int detail = SSL_get_error(x->s->ssl, rv);
    if(detail == SSL_ERROR_WANT_READ || detail == SSL_ERROR_WANT_WRITE) {
      return CURLE_AGAIN;
    }
    else if(detail == SSL_ERROR_ZERO_RETURN) {
      CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] h3_quic_recv -> EOS",
                  x->s->id);
      x->s->recvd_eos = TRUE;
      return CURLE_OK;
    }
    else if(SSL_get_stream_read_state(x->s->ssl) ==
            SSL_STREAM_STATE_RESET_REMOTE) {
      uint64_t app_error_code = NGHTTP3_H3_NO_ERROR;
      SSL_get_stream_read_error_code(x->s->ssl, &app_error_code);
      CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] h3_quic_recv -> RESET, "
                  "rv=%d, app_err=%" FMT_PRIu64,
                  x->s->id, rv, (curl_uint64_t)app_error_code);
      if(app_error_code != NGHTTP3_H3_NO_ERROR) {
        x->s->reset = TRUE;
      }
      x->s->recvd_eos = TRUE;
      return CURLE_OK;
    }
    else {
      return cf_osslq_ssl_err(x->cf, x->data, detail, CURLE_RECV_ERROR);
    }
  }
  return CURLE_OK;
}

static CURLcode cf_osslq_stream_recv(struct cf_osslq_stream *s,
                                     struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;
  size_t n;
  ssize_t nread;
  struct h3_quic_recv_ctx x;
  bool eagain = FALSE;
  size_t total_recv_len = 0;

  DEBUGASSERT(s);
  if(s->closed)
    return CURLE_OK;

  x.cf = cf;
  x.data = data;
  x.s = s;
  while(s->ssl && !s->closed && !eagain &&
         (total_recv_len < PROXY_H3_STREAM_CHUNK_SIZE)) {

    if(proxy_ctx->partial_read && s->id == proxy_ctx->tunnel.stream_id) {
      handle_buffered_data(cf, data);
      break;
    }

    if(Curl_bufq_is_empty(&s->recvbuf) && !s->recvd_eos) {
      while(!eagain && !s->recvd_eos && !Curl_bufq_is_full(&s->recvbuf)) {
        result = Curl_bufq_sipn(&s->recvbuf, 0, h3_quic_recv, &x, &n);
        if(result) {
          if(result != CURLE_AGAIN) {
            goto out;
          }
          result = CURLE_OK;
          eagain = TRUE;
        }
      }
    }

    /* At this point we can have 2 scenarios:
      (1) The proxytunnel is NOT yet UP and we are still negotiating the
          CONNECT request and the different unidirectional streams with
          the proxy. In this case, all the data must be forwarded to
          nghttp3 library for processing.
          Flow:
          cf_h3_proxy_quic_connect() --> proxy_h3_submit() -->
          proxy_h3_progress_egress() --> proxy_h3_progress_ingress() -->
          cf_osslq_h3conn_add_stream() --> cf_osslq_stream_recv() -->
          inspect_response() --> tunnel is UP (with bidi stream id = 0)
      (2) The proxytunnel is UP
          At this point, we have 7 streams - 1 bidi (the tunnel stream) and
          6 unidirectional streams (3 from curl and 3 from the proxy)
          Every "DATA" from the underlying HTTP/1.1 connection must be
          forwarded end-to-end through this HTTP/3 proxytunnel
          (i) Stream 0:
          <HTTP/1.1 data> === proxytunnel === <HTTP/3 headers>
                                              <HTTP/3 data> = <HTTP/1.1 data>
          (ii) Unidirectional Streams:
          can be terminated here, HTTP/1.1 layer is unaware of this
          Functions of Interest:
          (1) nghttp3_conn_read_stream --> this received HTTP/3 specific info
          (2) cb_h3_recv_data --> this received the actual end-to-end flow
                                      data from the server via the proxy
          nghttp3_conn_read_stream() internally invokes cb_h3_recv_data()
          In cb_h3_recv_data(), we are storing the "data" received w.r.t. to
          the HTTP/1.1 flow in cf_h3_proxy_ctx->inbufq
          Now, we need to propagate this up to the recv() call from the
          HTTP/1.1 SSL layer
          This is how the filter chain looks like:
          Curl_cft_http_connect --> Curl_cft_ssl --> ... --> Curl_cft_h3_proxy
    */

    /* Forward what we have to nghttp3 */
    if(!Curl_bufq_is_empty(&s->recvbuf)) {
      const unsigned char *buf;
      size_t blen;

      while(Curl_bufq_peek(&s->recvbuf, &buf, &blen)) {
        nread = nghttp3_conn_read_stream(ctx->h3.conn, s->id,
                                         buf, blen, 0);
        if(nread < 0) {
          failf(data, "nghttp3_conn_read_stream(len=%zu) error: %s",
                blen, nghttp3_strerror((int)nread));
          result = CURLE_OK;
          goto out;
        }

        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] stream %ld, received %zd "
                      "bytes, DATA bytes = %zu, forwarded to nghttp3 = %zd",
                      s->id, s->id, blen, (blen - nread), nread);

        Curl_bufq_skip(&s->recvbuf, blen);
        total_recv_len += blen;

        if(Curl_bufq_is_empty(&s->recvbuf) || proxy_ctx->partial_read)
          break;
      }
    }

    /* When we forwarded everything, handle RESET/EOS */
    if(Curl_bufq_is_empty(&s->recvbuf) && !s->closed) {
      int rv;
      result = CURLE_OK;
      if(s->reset) {
        uint64_t app_error;
        if(!SSL_get_stream_read_error_code(s->ssl, &app_error)) {
          failf(data, "SSL_get_stream_read_error_code returned error");
          result = CURLE_RECV_ERROR;
          goto out;
        }
        rv = nghttp3_conn_close_stream(ctx->h3.conn, s->id, app_error);
        s->closed = TRUE;
        if(rv < 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
          failf(data, "nghttp3_conn_close_stream returned error: %s",
                nghttp3_strerror(rv));
          result = CURLE_RECV_ERROR;
          goto out;
        }
      }
      else if(s->recvd_eos) {
        rv = nghttp3_conn_close_stream(ctx->h3.conn, s->id,
                                       NGHTTP3_H3_NO_ERROR);
        s->closed = TRUE;
        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] close nghttp3 stream -> %d",
                    s->id, rv);
        if(rv < 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
          failf(data, "nghttp3_conn_close_stream returned error: %s",
                nghttp3_strerror(rv));
          result = CURLE_RECV_ERROR;
          goto out;
        }
      }
    }
  }
out:
  return result;
}

struct cf_ossq_recv_ctx {
  struct Curl_cfilter *cf;
  struct Curl_multi *multi;
  CURLcode result;
};

static bool cf_osslq_iter_recv(unsigned int mid, void *val, void *user_data)
{
  struct h3_proxy_stream_ctx *stream = val;
  struct cf_ossq_recv_ctx *rctx = user_data;

  (void)mid;
  if(stream && !stream->closed && !Curl_bufq_is_full(&stream->recvbuf)) {
    struct Curl_easy *sdata = Curl_multi_get_easy(rctx->multi, mid);
    if(sdata) {
      rctx->result = cf_osslq_stream_recv(&stream->s, rctx->cf, sdata);
      if(rctx->result)
        return FALSE; /* abort iteration */
    }
  }
  return TRUE;
}

static CURLcode proxy_h3_progress_ingress(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;

  if(!ctx->tls.ossl.ssl)
    goto out;

  ERR_clear_error();

  /* Check for new incoming streams, once the proxy tunnel stream
     and the 3 unidirectional streams (CONTROL, QPACK DEC & ENC)
     are setup, we do not expect to accept any more stream */
  if(!proxy_ctx->connected && ctx->h3.remote_ctrl_n < 3) {
    while(1) {
      SSL *snew = SSL_accept_stream(ctx->tls.ossl.ssl,
                                    SSL_ACCEPT_STREAM_NO_BLOCK);
      if(!snew)
        break;

      (void)cf_osslq_h3conn_add_stream(&ctx->h3, snew, cf, data);
    }
  }

  if(!SSL_handle_events(ctx->tls.ossl.ssl)) {
    int detail = SSL_get_error(ctx->tls.ossl.ssl, 0);
    result = cf_osslq_ssl_err(cf, data, detail, CURLE_RECV_ERROR);
  }

  if(ctx->h3.conn) {
    size_t i;
    for(i = 0; i < ctx->h3.remote_ctrl_n; ++i) {
      result = cf_osslq_stream_recv(&ctx->h3.remote_ctrl[i], cf, data);
      if(result)
        goto out;
    }
  }

  if(ctx->h3.conn) {
    struct cf_ossq_recv_ctx rctx;

    DEBUGASSERT(data->multi);
    rctx.cf = cf;
    rctx.multi = data->multi;
    rctx.result = CURLE_OK;
    Curl_uint_hash_visit(&ctx->streams, cf_osslq_iter_recv, &rctx);
    result = rctx.result;
  }

out:
  CURL_TRC_CF(data, cf, "progress_ingress -> %d", result);
  return result;
}

struct cf_ossq_fill_ctx {
  struct cf_osslq_ctx *ctx;
  struct Curl_multi *multi;
  size_t n;
};

static bool cf_osslq_collect_block_send(unsigned int mid, void *val,
                                        void *user_data)
{
  struct h3_proxy_stream_ctx *stream = val;
  struct cf_ossq_fill_ctx *fctx = user_data;
  struct cf_osslq_ctx *ctx = fctx->ctx;

  if(fctx->n >= ctx->items_max)  /* should not happen, prevent mayhem */
    return FALSE;

  if(stream && stream->s.ssl && stream->s.send_blocked) {
    struct Curl_easy *sdata = Curl_multi_get_easy(fctx->multi, mid);
    if(sdata) {
      ctx->poll_items[fctx->n].desc = SSL_as_poll_descriptor(stream->s.ssl);
      ctx->poll_items[fctx->n].events = SSL_POLL_EVENT_W;
      ctx->curl_items[fctx->n] = sdata;
      fctx->n++;
    }
  }
  return TRUE;
}

/* Iterate over all streams and check if blocked can be unblocked */
static CURLcode cf_osslq_check_and_unblock(struct Curl_cfilter *cf,
                                            struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream;
    size_t poll_count;
  size_t result_count = 0;
  size_t idx_count = 0;
  CURLcode res = CURLE_OK;
  struct timeval timeout;
  void *tmpptr;

  if(ctx->h3.conn) {
    struct cf_ossq_fill_ctx fill_ctx;

    if(ctx->items_max < Curl_uint_hash_count(&ctx->streams)) {
      size_t nmax = Curl_uint_hash_count(&ctx->streams);
      ctx->items_max = 0;
      tmpptr = realloc(ctx->poll_items, nmax * sizeof(SSL_POLL_ITEM));
      if(!tmpptr) {
        free(ctx->poll_items);
        ctx->poll_items = NULL;
        res = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      ctx->poll_items = tmpptr;

      tmpptr = realloc(ctx->curl_items, nmax * sizeof(struct Curl_easy *));
      if(!tmpptr) {
        free(ctx->curl_items);
        ctx->curl_items = NULL;
        res = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      ctx->curl_items = tmpptr;
      ctx->items_max = nmax;
    }

    fill_ctx.ctx = ctx;
    fill_ctx.multi = data->multi;
    fill_ctx.n = 0;
    Curl_uint_hash_visit(&ctx->streams, cf_osslq_collect_block_send,
                          &fill_ctx);
    poll_count = fill_ctx.n;
    if(poll_count) {
      CURL_TRC_CF(data, cf, "polling %zu blocked streams", poll_count);

      memset(&timeout, 0, sizeof(struct timeval));
      res = CURLE_UNRECOVERABLE_POLL;
      if(!SSL_poll(ctx->poll_items, poll_count, sizeof(SSL_POLL_ITEM),
                    &timeout, 0, &result_count))
        goto out;

      res = CURLE_OK;

      for(idx_count = 0; idx_count < poll_count && result_count > 0;
            idx_count++) {
        if(ctx->poll_items[idx_count].revents & SSL_POLL_EVENT_W) {
          stream = H3_PROXY_STREAM_CTX(ctx, ctx->curl_items[idx_count]);
          DEBUGASSERT(stream); /* should still exist */
          if(stream) {
            nghttp3_conn_unblock_stream(ctx->h3.conn, stream->s.id);
            stream->s.send_blocked = FALSE;
            Curl_multi_mark_dirty(ctx->curl_items[idx_count]);
            CURL_TRC_CF(ctx->curl_items[idx_count], cf, "unblocked");
          }
          result_count--;
        }
      }
    }
  }

out:
  return res;
}

static CURLcode h3_send_streams(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;

  if(!ctx->tls.ossl.ssl || !ctx->h3.conn)
    goto out;

  for(;;) {
    struct cf_osslq_stream *s = NULL;
    nghttp3_vec vec[16];
    nghttp3_ssize n, i;
    int64_t stream_id;
    size_t written;
    int eos, ok, rv;
    size_t total_len, acked_len = 0;
    bool blocked = FALSE, eos_written = FALSE;

    n = nghttp3_conn_writev_stream(ctx->h3.conn, &stream_id, &eos,
                                   vec, ARRAYSIZE(vec));
    if(n < 0) {
      failf(data, "nghttp3_conn_writev_stream returned error: %s",
            nghttp3_strerror((int)n));
      result = CURLE_SEND_ERROR;
      goto out;
    }
    if(stream_id < 0) {
      result = CURLE_OK;
      goto out;
    }

    /* Get the stream for this data */
    s = cf_osslq_get_qstream(cf, data, stream_id);
    if(!s) {
      failf(data, "nghttp3_conn_writev_stream gave unknown stream %"
                  FMT_PRId64, (curl_int64_t)stream_id);
      result = CURLE_SEND_ERROR;
      goto out;
    }
    /* Now write the data to the stream's SSL*, it may not all fit! */
    DEBUGASSERT(s->id == stream_id);
    for(i = 0, total_len = 0; i < n; ++i)
      total_len += vec[i].len;

    for(i = 0; (i < n) && !blocked; ++i) {
      /* Without stream->s.ssl, we closed that already, so
       * pretend the write did succeed. */
      uint64_t flags = (eos && ((i + 1) == n)) ? SSL_WRITE_FLAG_CONCLUDE : 0;
      if(stream_id == proxy_ctx->tunnel.stream_id)
        eos = 0;

      written = vec[i].len;
      ok = !s->ssl || SSL_write_ex2(s->ssl, vec[i].base, vec[i].len, flags,
                                    &written);
      if(ok) {
        /* As OpenSSL buffers the data, we count this as acknowledged
         * from nghttp3's point of view */
        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send %zu bytes to QUIC ok",
                    s->id, vec[i].len);
        acked_len += vec[i].len;
      }
      else {
        int detail = SSL_get_error(s->ssl, 0);
        switch(detail) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          /* QUIC blocked us from writing more */
          CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send %zu bytes to "
                                "QUIC blocked",
                      s->id, vec[i].len);
          written = 0;
          nghttp3_conn_block_stream(ctx->h3.conn, s->id);
          s->send_blocked = blocked = TRUE;
          break;
        default:
          failf(data, "[%" FMT_PRId64 "] send %zu bytes to QUIC, SSL error %d",
                s->id, vec[i].len, detail);
          result = cf_osslq_ssl_err(cf, data, detail, CURLE_HTTP3);
          goto out;
        }
      }
    }

    if(acked_len > 0 || (eos && !s->send_blocked)) {
      /* Since QUIC buffers the data written internally, we can tell
       * nghttp3 that it can move forward on it */
      ctx->q.last_io = curlx_now();
      rv = nghttp3_conn_add_write_offset(ctx->h3.conn, s->id, acked_len);
      if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
        failf(data, "nghttp3_conn_add_write_offset returned error: %s\n",
              nghttp3_strerror(rv));
        result = CURLE_SEND_ERROR;
        goto out;
      }
      rv = nghttp3_conn_add_ack_offset(ctx->h3.conn, s->id, acked_len);
      if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
        failf(data, "nghttp3_conn_add_ack_offset returned error: %s\n",
              nghttp3_strerror(rv));
        result = CURLE_SEND_ERROR;
        goto out;
      }
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] forwarded %zu/%zu h3 bytes "
                            "to QUIC, eos=%d",
                  s->id, acked_len, total_len, eos);
    }

    if(eos && !s->send_blocked && !eos_written) {
      /* wrote everything and H3 indicates end of stream */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] closing QUIC stream", s->id);
      SSL_stream_conclude(s->ssl, 0);
    }
  }

out:
  CURL_TRC_CF(data, cf, "h3_send_streams -> %d", result);
  return result;
}

static CURLcode proxy_h3_progress_egress(struct Curl_cfilter *cf,
                                         struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;

  if(!ctx->tls.ossl.ssl)
    goto out;

  ERR_clear_error();
  result = h3_send_streams(cf, data);
  if(result)
    goto out;

  if(!SSL_handle_events(ctx->tls.ossl.ssl)) {
    int detail = SSL_get_error(ctx->tls.ossl.ssl, 0);
    result = cf_osslq_ssl_err(cf, data, detail, CURLE_SEND_ERROR);
  }

  result = cf_osslq_check_and_unblock(cf, data);

out:
  CURL_TRC_CF(data, cf, "progress_egress -> %d", result);
  return result;
}

static CURLcode check_and_set_expiry(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;
  struct timeval tv;
  timediff_t timeoutms;
  int is_infinite = 1;

  if(ctx->tls.ossl.ssl &&
      SSL_get_event_timeout(ctx->tls.ossl.ssl, &tv, &is_infinite) &&
      !is_infinite) {
    timeoutms = curlx_tvtoms(&tv);
    /* QUIC want to be called again latest at the returned timeout */
    if(timeoutms <= 0) {
      result = proxy_h3_progress_ingress(cf, data);
      if(result)
        goto out;
      result = proxy_h3_progress_egress(cf, data);
      if(result)
        goto out;
      if(SSL_get_event_timeout(ctx->tls.ossl.ssl, &tv, &is_infinite)) {
        timeoutms = curlx_tvtoms(&tv);
      }
    }
    if(!is_infinite) {
      Curl_expire(data, timeoutms, EXPIRE_QUIC);
      CURL_TRC_CF(data, cf, "QUIC expiry in %ldms", (long)timeoutms);
    }
  }
out:
  return result;
}

static CURLcode recv_closed_stream(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_proxy_stream_ctx *stream,
                                   size_t *pnread)
{
  (void)cf;
  *pnread = 0;
  if(stream->reset) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64 " reset by server",
          stream->s.id);
    return data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64
          " was closed cleanly, but before getting"
          " all response header fields, treated as error",
          stream->s.id);
    return CURLE_HTTP3;
  }
  return CURLE_OK;
}

static CURLcode cf_h3_proxy_send(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const void *buf, size_t len, bool eos,
                                size_t *pnwritten)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;

  *pnwritten = -1;

  if(proxy_ctx->tunnel.closed)
    return CURLE_SEND_ERROR;

  (void)eos; /* use to end stream */
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->tls.ossl.ssl);
  DEBUGASSERT(ctx->h3.conn);

  if(!stream) {
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] discarding data"
                            "on closed stream with response",
                  stream->s.id);
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send_body(len=%zu) "
                          "-> stream closed",
                stream->s.id, len);
    result = CURLE_HTTP3;
    goto out;
  }
  else {
    if(data->conn->bits.udp_tunnel_proxy) {
      struct dynbuf dyn;

      result = curl_capsule_encap_udp_datagram(&dyn, buf, len);
      if(result)
        goto out;

      result = Curl_bufq_write(&stream->sendbuf,
                                 (const unsigned char *)curlx_dyn_ptr(&dyn),
                                 curlx_dyn_len(&dyn), pnwritten);
      curlx_dyn_free(&dyn);
    }
    else {
      result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_h3_proxy_send, add to "
                          "sendbuf(len=%zu) -> %zd, %d",
                stream->s.id, len, *pnwritten, result);

    if(result) {
      goto out;
    }
    stream->upload_left += *pnwritten;

    (void)nghttp3_conn_resume_stream(ctx->h3.conn, stream->s.id);
  }

  result = Curl_1st_err(result, proxy_h3_progress_ingress(cf, data));

  result = Curl_1st_err(result, proxy_h3_progress_egress(cf, data));

out:
  result = Curl_1st_err(result, check_and_set_expiry(cf, data));
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_h3_proxy_send(len=%zu)"
                        " -> %zd, %d",
              stream ? stream->s.id : -1, len, *pnwritten, result);

  return result;
}

static ssize_t process_udp_capsule(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   char *buf, size_t len, CURLcode *err)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;

  return curl_capsule_process_udp(cf, data, &proxy_ctx->inbufq, buf, len, err);
}

static CURLcode cf_h3_proxy_recv(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len, size_t *pnread)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;

  *pnread = 0;

  if(proxy_ctx->tunnel.closed)
    return CURLE_RECV_ERROR;

  (void)ctx;
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->tls.ossl.ssl);
  DEBUGASSERT(ctx->h3.conn);

  if(!stream) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(!data->conn->bits.udp_tunnel_proxy) {
    if(!Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
      result = Curl_bufq_cread(&proxy_ctx->inbufq,
                              buf, len, pnread);
      if(result)
        goto out;
    }
  }

  result = Curl_1st_err(result, proxy_h3_progress_ingress(cf, data));
  if(result)
    goto out;

  if(data->conn->bits.udp_tunnel_proxy) {
    if(Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
      /* No data to process */
      result = CURLE_AGAIN;
      goto out;
    }

    *pnread = process_udp_capsule(cf, data, buf, len, &result);
    goto out;
  }

  /* recvbuf had nothing before, maybe after progressing ingress? */
  if(!*pnread && !Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
    result = Curl_bufq_cread(&proxy_ctx->inbufq,
                             buf, len, pnread);
    if(result) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read recvbuf(len=%zu) "
                            "-> %zd, %d",
                  stream->s.id, len, *pnread, result);
      goto out;
    }
  }

  if(*pnread) {
    Curl_multi_mark_dirty(data);
  }
  else {
    if(stream->closed) {
      result = recv_closed_stream(cf, data, stream, pnread);
      goto out;
    }
    result = CURLE_AGAIN;
  }

out:
  result = Curl_1st_err(result, proxy_h3_progress_egress(cf, data));
  result = Curl_1st_err(result, check_and_set_expiry(cf, data));

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_h3_proxy_recv(len=%zu) -> "
                        " %zd, %d",
              stream ? stream->s.id : -1,
              len, *pnread, result);
  return result;
}

static void proxy_h3_submit(curl_int64_t *pstream_id,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct httpreq *req,
                            CURLcode *err)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
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

  *err = h3_data_setup(cf, data);
  if(*err)
    goto out;
  stream = H3_PROXY_STREAM_CTX(ctx, data);

  DEBUGASSERT(stream);
  if(!stream) {
    *err = CURLE_FAILED_INIT;
    goto out;
  }

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(nghttp3_nv) * nheader);
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

  DEBUGASSERT(stream->s.id == -1);
  *err = cf_osslq_stream_open(&stream->s, ctx->tls.ossl.ssl, 0,
                              &ctx->stream_bufcp, data);
  if(*err) {
    failf(data, "cannot get bidi streams");
    *err = CURLE_SEND_ERROR;
    goto out;
  }
  stream->s.tunnel_stream = TRUE;

  /* this is a CONNECT request, there is no request body */
  stream->upload_left = 0;
  stream->send_closed = 0;
  reader.read_data = cb_h3_read_data_for_tunnel_stream;
  preader = &reader;

  rc = nghttp3_conn_submit_request(ctx->h3.conn, stream->s.id,
                                   nva, nheader, preader, data);
  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send, "
                            "connection is closing",
                  stream->s.id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send -> %d (%s)",
                  stream->s.id, rc, nghttp3_strerror(rc));
      break;
    }
    *err = CURLE_SEND_ERROR;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    CURL_TRC_CF(data, cf, "[H3-PROXY] [%" FMT_PRId64 "] OPENED stream "
                "for %s", stream->s.id, data->state.url);
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  if(*err == CURLE_OK) {
    *pstream_id = stream->s.id;
  }
}

static bool cf_h3_proxy_is_alive(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *input_pending)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  bool alive = FALSE;

  *input_pending = FALSE;
  if(!ctx->tls.ossl.ssl)
    goto out;

#ifdef SSL_VALUE_QUIC_IDLE_TIMEOUT
  /* Added in OpenSSL v3.3.x */
  {
    timediff_t idletime;
    uint64_t idle_ms = ctx->max_idle_ms;
    if(!SSL_get_value_uint(ctx->tls.ossl.ssl,
                            SSL_VALUE_CLASS_FEATURE_NEGOTIATED,
                            SSL_VALUE_QUIC_IDLE_TIMEOUT, &idle_ms)) {
      CURL_TRC_CF(data, cf, "error getting negotiated idle timeout, "
                            "assume connection is dead.");
      goto out;
    }
    CURL_TRC_CF(data, cf, "negotiated idle timeout: %zums", (size_t)idle_ms);
    idletime = curlx_timediff(curlx_now(), ctx->q.last_io);
    if(idletime > 0 && (uint64_t)idletime > idle_ms)
      goto out;
  }

#endif

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    goto out;

  alive = TRUE;
  if(*input_pending) {
    CURLcode result;
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
    result = proxy_h3_progress_ingress(cf, data);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result ? FALSE : TRUE;
  }

out:
  return alive;
}

static CURLcode cf_h3_proxy_query(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   int query, int *pres1, void *pres2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT:
  {
#ifdef SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL
    /* Added in OpenSSL v3.3.x */
    uint64_t v;
    if(ctx->tls.ossl.ssl &&
       !SSL_get_value_uint(ctx->tls.ossl.ssl, SSL_VALUE_CLASS_GENERIC,
                           SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL, &v)) {
      CURL_TRC_CF(data, cf, "error getting available local bidi streams");
      return CURLE_HTTP3;
    }
    /* we report avail + in_use */
    v += CONN_INUSE(cf->conn);
    *pres1 = (v > INT_MAX) ? INT_MAX : (int)v;
#else
    *pres1 = 100;
#endif
    CURL_TRC_CF(data, cf, "query max_conncurrent -> %d", *pres1);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->got_first_byte) {
      timediff_t ms = curlx_timediff(ctx->first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT:
  {
    struct curltime *when = pres2;
    if(ctx->got_first_byte)
      *when = ctx->first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT:
  {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HOST_PORT:
    *pres1 = (int)cf->conn->http_proxy.port;
    *((const char **)pres2) = cf->conn->http_proxy.host.name;
    return CURLE_OK;
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = cf->connected ? "h3" : NULL;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 31;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO: {
    struct curl_tlssessioninfo *info = pres2;
    if(Curl_vquic_tls_get_ssl_info(&ctx->tls,
                (query == CF_QUERY_SSL_CTX_INFO), info))
      return CURLE_OK;
    break;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static CURLcode cf_h3_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct easy_pollset *ps)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;

  if(!ctx || !ctx->tls.ossl.ssl) {
    /* NOP */
  }
  else if(!cf->connected) {
    result = Curl_pollset_set(data, ps, ctx->q.sockfd,
                              SSL_net_read_desired(ctx->tls.ossl.ssl),
                              SSL_net_write_desired(ctx->tls.ossl.ssl));
  }
  else {
    bool want_recv, want_send;
    Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
    if(want_recv || want_send) {
      result = Curl_pollset_set(data, ps, ctx->q.sockfd,
                                SSL_net_read_desired(ctx->tls.ossl.ssl),
                                SSL_net_write_desired(ctx->tls.ossl.ssl));
    }
    else if(ctx->need_recv || ctx->need_send) {
      result = Curl_pollset_set(data, ps, ctx->q.sockfd,
                                ctx->need_recv, ctx->need_send);
    }
  }
  return result;
}

static bool cf_h3_proxy_data_pending(struct Curl_cfilter *cf,
                                     const struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  const struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  (void)cf;
  return stream && !Curl_bufq_is_empty(&stream->recvbuf);
}

static CURLcode cf_h3_proxy_ctx_init(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx;
  int rv;
  CURLcode result = CURLE_OK;
  const struct Curl_sockaddr_ex *peer_addr = NULL;
  BIO *bio = NULL;
  BIO_ADDR *baddr = NULL;
  static const struct alpn_spec ALPN_SPEC_H3 = {
    { "h3" }, 1
  };

  ctx = calloc(1, sizeof(struct cf_osslq_ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_osslq_ctx_init(ctx);

  memset(&proxy_ctx->tunnel, 0, sizeof(proxy_ctx->tunnel));

  Curl_bufq_init(&proxy_ctx->inbufq, PROXY_H3_STREAM_CHUNK_SIZE,
                 H3_TUNNEL_RECV_CHUNKS);

  if(tunnel_stream_init(cf, &proxy_ctx->tunnel))
    goto out;

  DEBUGASSERT(ctx->initialized);

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               &ALPN_SPEC_H3, NULL, NULL, NULL, NULL);
  if(result)
    goto out;

  result = vquic_ctx_init(&ctx->q);
  if(result)
    goto out;

  result = CURLE_QUIC_CONNECT_ERROR;
  Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &peer_addr, NULL);
  if(!peer_addr)
    goto out;

  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                  &ctx->q.local_addrlen);
  if(rv == -1)
    goto out;

  result = make_bio_addr(&baddr, peer_addr);
  if(result) {
    failf(data, "error creating BIO_ADDR from sockaddr");
    goto out;
  }
/* Type conversions, see #12861: OpenSSL wants an `int`, but on 64-bit
  * Win32 systems, Microsoft defines SOCKET as `unsigned long long`.
*/
#if defined(_WIN32) && !defined(__LWIP_OPT_H__) && !defined(LWIP_HDR_OPT_H)
  if(ctx->q.sockfd > INT_MAX) {
    failf(data, "Windows socket identifier larger than MAX_INT, "
          "unable to set in OpenSSL dgram API.");
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  bio = BIO_new_dgram((int)ctx->q.sockfd, BIO_NOCLOSE);
#else
  bio = BIO_new_dgram(ctx->q.sockfd, BIO_NOCLOSE);
#endif
  if(!bio) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(!SSL_set1_initial_peer_addr(ctx->tls.ossl.ssl, baddr)) {
    failf(data, "failed to set the initial peer address");
    result = CURLE_FAILED_INIT;
    goto out;
  }
  if(!SSL_set_blocking_mode(ctx->tls.ossl.ssl, 0)) {
    failf(data, "failed to turn off blocking mode");
    result = CURLE_FAILED_INIT;
    goto out;
  }

  SSL_set_bio(ctx->tls.ossl.ssl, bio, bio);
  bio = NULL;
  SSL_set_connect_state(ctx->tls.ossl.ssl);
  SSL_set_incoming_stream_policy(ctx->tls.ossl.ssl,
                                  SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
  /* setup the H3 things on top of the QUIC connection */
  result = cf_osslq_h3conn_init(ctx, ctx->tls.ossl.ssl, cf);
  proxy_ctx->osslq_ctx = ctx;
  proxy_ctx->partial_read = FALSE;
  proxy_ctx->connected = FALSE;

out:
  if(bio)
    BIO_free(bio);
  if(baddr)
    BIO_ADDR_free(baddr);
  CURL_TRC_CF(data, cf, "QUIC tls init -> %d", result);
  CURL_TRC_CF(data, cf, "[0] init proxy ctx -> %d", result);
  return result;
}

static CURLcode submit_CONNECT(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct tunnel_stream *ts)
{
  CURLcode result;
  struct httpreq *req = NULL;

  if(cf->conn->bits.udp_tunnel_proxy) {
    result = Curl_http_proxy_create_CONNECTUDP(&req, cf, data, 3);
  }
  else {
    result = Curl_http_proxy_create_CONNECT(&req, cf, data, 3);
  }
  if(result)
    goto out;
  result = Curl_creader_set_null(data);
  if(result)
    goto out;

  if(cf->conn->bits.udp_tunnel_proxy)
    infof(data, "Establishing HTTP/3 proxy UDP tunnel to %s:%s",
                        data->state.up.hostname, data->state.up.port);
  else
    infof(data, "Establishing HTTP/3 proxy tunnel to %s", req->authority);

  proxy_h3_submit(&ts->stream_id, cf, data, req, &result);

out:
  if(req)
    Curl_http_req_free(req);
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  return result;
}

static CURLcode
inspect_response(struct Curl_cfilter *cf,
                 struct Curl_easy *data,
                 struct tunnel_stream *ts)
{
  CURLcode result = CURLE_OK;
  struct dynhds_entry *auth_reply = NULL;
  struct dynhds_entry *capsule_protocol = NULL;
  size_t i, header_count;
  (void)cf;

  DEBUGASSERT(ts->resp);

  /* Log all response headers */
  if(cf->conn->bits.udp_tunnel_proxy)
    infof(data, "CONNECT-UDP Response Status %d", ts->resp->status);
  else
    infof(data, "CONNECT Response Status %d", ts->resp->status);
  header_count = Curl_dynhds_count(&ts->resp->headers);
  infof(data, "Response Headers (%zu total):", header_count);
  for(i = 0; i < header_count; i++) {
    struct dynhds_entry *entry = Curl_dynhds_getn(&ts->resp->headers, i);
    if(entry)
      infof(data, "  %s: %s", entry->name, entry->value);
  }

  if(cf->conn->bits.udp_tunnel_proxy) {
    if(ts->resp->status == 200) {
      capsule_protocol = Curl_dynhds_cget(&ts->resp->headers,
                                          "capsule-protocol");
      if(capsule_protocol) {
        if(strncmp(capsule_protocol->value, "?1", 2) == 0) {
          CURL_TRC_CF(data, cf, "CONNECT-UDP tunnel established, "
                    "response %d", ts->resp->status);
          h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
          return CURLE_OK;
        }
      }
      else {
        /* NOTE proxies may not set capsule protocol in the headers */
        CURL_TRC_CF(data, cf, "CONNECT-UDP tunnel established, response %d"
                    "but no capsule-protocol header found", ts->resp->status);
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
        return CURLE_OK;
      }
    }
    else {
        CURL_TRC_CF(data, cf, "Failed to establish CONNECT-UDP tunnel, "
                "response %d", ts->resp->status);
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
        return CURLE_RECV_ERROR;
    }
  }
  else {
    if(ts->resp->status / 100 == 2) {
      CURL_TRC_CF(data, cf, "CONNECT tunnel established, response %d",
                  ts->resp->status);
      h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
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
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_INIT, data);
        return CURLE_OK;
      }
    }
  }

  /* Seems to have failed */
  return CURLE_RECV_ERROR;
}

static CURLcode cf_h3_proxy_quic_connect(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct curltime now;
  int err;

  if(cf->connected) {
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
  now = curlx_now();

  if(!proxy_ctx->osslq_ctx) {
    result = cf_h3_proxy_ctx_init(cf, data);
    if(result)
      return result;
  }

  if(!proxy_ctx->osslq_ctx->got_first_byte) {
    int readable = SOCKET_READABLE(proxy_ctx->osslq_ctx->q.sockfd, 0);
    if(readable > 0 && (readable & CURL_CSELECT_IN)) {
      proxy_ctx->osslq_ctx->got_first_byte = TRUE;
      proxy_ctx->osslq_ctx->first_byte_at = curlx_now();
    }
  }

  /* Since OpenSSL does its own send/recv internally, we may miss the
   * moment to populate the x509 store right before the server response.
   * Do it instead before we start the handshake, at the loss of the
   * time to set this up. */
  result = Curl_vquic_tls_before_recv(&proxy_ctx->osslq_ctx->tls, cf, data);
  if(result)
    goto out;

  ERR_clear_error();

  err = SSL_do_handshake(proxy_ctx->osslq_ctx->tls.ossl.ssl);

  if(err == 1) {
    /* connected */
    proxy_ctx->osslq_ctx->handshake_at = now;
    proxy_ctx->osslq_ctx->q.last_io = now;

    CURL_TRC_CF(data, cf, "handshake complete after %dms",
                (int)curlx_timediff(now, proxy_ctx->osslq_ctx->started_at));
    result = cf_osslq_verify_peer(cf, data);
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }
  else {
    int detail = SSL_get_error(proxy_ctx->osslq_ctx->tls.ossl.ssl, err);
    switch(detail) {
    case SSL_ERROR_WANT_READ:
      proxy_ctx->osslq_ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_RECV");
      goto out;
    case SSL_ERROR_WANT_WRITE:
      proxy_ctx->osslq_ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_SEND");
      result = CURLE_OK;
      goto out;
#ifdef SSL_ERROR_WANT_ASYNC
    case SSL_ERROR_WANT_ASYNC:
      proxy_ctx->osslq_ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_ASYNC");
      result = CURLE_OK;
      goto out;
#endif
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    case SSL_ERROR_WANT_RETRY_VERIFY:
      result = CURLE_OK;
      goto out;
#endif
    default:
      result = cf_osslq_ssl_err(cf, data, detail, CURLE_COULDNT_CONNECT);
      goto out;
    }
  }

out:
  if(result == CURLE_RECV_ERROR && proxy_ctx->osslq_ctx->tls.ossl.ssl &&
      proxy_ctx->osslq_ctx->protocol_shutdown) {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state. The CONNECT may work in the near future again. Indicate
     * that as a "weird" reply. */
    result = CURLE_WEIRD_SERVER_REPLY;
  }

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result) {
    if(cf->next->cft == &Curl_cft_udp) {
      struct ip_quadruple ip;

      Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
      failf(data, "QUIC connect to %s port %u failed: %s",
            ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
    }
    else {
      failf(data, "QUIC connect failed, issue with filter chain, "
                  "could not find Curl_cft_udp filter");
    }
  }
#endif
  /* Maybe extreme but avoid seding data before quic handshake is done */
  if(!result && !SSL_in_init(proxy_ctx->osslq_ctx->tls.ossl.ssl))
    result = check_and_set_expiry(cf, data);
  if(result || *done) {
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  }

  return result;
}

static CURLcode H3_CONNECT(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct tunnel_stream *ts)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(ts);
  DEBUGASSERT(ts->authority);

  do {
    switch(ts->state) {
    case H3_TUNNEL_INIT:
      CURL_TRC_CF(data, cf, "[0] CONNECT start for %s", ts->authority);
      result = submit_CONNECT(cf, data, ts);
      if(result)
        goto out;
      h3_tunnel_go_state(cf, ts, H3_TUNNEL_CONNECT, data);

      result = proxy_h3_progress_egress(cf, data);
      if(result)
        goto out;
      FALLTHROUGH();

    case H3_TUNNEL_CONNECT:
      while(ts->has_final_response == FALSE) {
        result = proxy_h3_progress_ingress(cf, data);
        if(result)
          goto out;
        result = proxy_h3_progress_egress(cf, data);
        if(result && result != CURLE_AGAIN) {
          h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
          goto out;
        }
      }
      if(result && result != CURLE_AGAIN) {
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
        break;
      }

      if(ts->has_final_response)
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_RESPONSE, data);
      else {
        result = CURLE_OK;
        goto out;
      }
      FALLTHROUGH();

    case H3_TUNNEL_RESPONSE:
      DEBUGASSERT(ts->has_final_response);
      result = inspect_response(cf, data, ts);
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
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
  return result;
}

static CURLcode
cf_h3_proxy_connect(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  timediff_t check;
  struct tunnel_stream *ts = &proxy_ctx->tunnel;

  /* Curl_cft_http_proxy --> Curl_cft_h3_proxy --> Curl_cft_udp */
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;

  check = Curl_timeleft(data, NULL, TRUE);
  if(check <= 0) {
    failf(data, "Proxy CONNECT aborted due to timeout");
    result = CURLE_OPERATION_TIMEDOUT;
    goto out;
  }

  result = cf_h3_proxy_quic_connect(cf, data, done);
  if(*done != TRUE)
    goto out;

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

  return result;
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
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

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

  (void)cf;
  if(stream && stream->s.id == proxy_ctx->tunnel.stream_id) {
    if(ctx->h3.conn && !stream->closed) {
      nghttp3_conn_shutdown_stream_read(ctx->h3.conn, stream->s.id);
      nghttp3_conn_close_stream(ctx->h3.conn, stream->s.id,
                                NGHTTP3_H3_REQUEST_CANCELLED);
      nghttp3_conn_set_stream_user_data(ctx->h3.conn, stream->s.id, NULL);
      proxy_ctx->tunnel.closed = TRUE;
    }

    Curl_uint_hash_remove(&ctx->streams, data->mid);
  }
}

static CURLcode cf_h3_proxy_cntrl(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  int event, int arg1, void *arg2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(stream && !stream->send_closed) {
      stream->send_closed = TRUE;
      stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
        stream->sendbuf_len_in_flight;
      (void)nghttp3_conn_resume_stream(ctx->h3.conn, stream->s.id);
    }
    break;
  }
  case CF_CTRL_DATA_IDLE: {
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    CURL_TRC_CF(data, cf, "data idle");
    if(stream && !stream->closed) {
      result = check_and_set_expiry(cf, data);
    }
    break;
  }
  default:
    break;
  }

  return result;
}

static void cf_h3_proxy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    /* Clean up the osslq context properly */
    if(ctx->osslq_ctx) {
      CURL_TRC_CF(data, cf, "cf_osslq_ctx_close()");
      if(ctx->osslq_ctx->tls.ossl.ssl)
        cf_osslq_ctx_close(ctx->osslq_ctx);
      cf_osslq_ctx_free(ctx->osslq_ctx);
      ctx->osslq_ctx = NULL;
    }
    cf_h3_proxy_ctx_free(ctx);
    cf->ctx = NULL;
  }
}

static void cf_h3_proxy_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  if(ctx) {
    cf_h3_proxy_ctx_clear(ctx);
    cf->connected = FALSE;
  }

  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
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

static struct Curl_addrinfo *
addr_first_match(struct Curl_addrinfo *addr, int family)
{
  while(addr) {
    if(addr->ai_family == family)
      return addr;
    addr = addr->ai_next;
  }
  return NULL;
}

static int Curl_get_QUIC_addr_info(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct Curl_addrinfo *ai)
{
  struct connectdata *conn = cf->conn;
  struct Curl_dns_entry *remotehost = data->state.dns[cf->sockindex];
  int ai_family0 = 0, ai_family1 = 0;
  const struct Curl_addrinfo *addr0 = NULL, *addr1 = NULL;

  if(conn->ip_version == CURL_IPRESOLVE_V6) {
#ifdef USE_IPV6
    ai_family0 = AF_INET6;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
#endif
  }
  else if(conn->ip_version == CURL_IPRESOLVE_V4) {
    ai_family0 = AF_INET;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
  }
  else {
    /* no user preference, we try ipv6 always first when available */
#ifdef USE_IPV6
    ai_family0 = AF_INET6;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
#endif
    /* next candidate is ipv4 */
    ai_family1 = AF_INET;
    addr1 = addr_first_match(remotehost->addr, ai_family1);
    /* no ip address families, probably AF_UNIX or something, use the
     * address family given to us */
    if(!addr1  && !addr0 && remotehost->addr) {
      ai_family0 = remotehost->addr->ai_family;
      addr0 = addr_first_match(remotehost->addr, ai_family0);
    }
  }

  if(!addr0 && addr1) {
    /* switch around, so a single baller always uses addr0 */
    addr0 = addr1;
    ai_family0 = ai_family1;
    addr1 = NULL;
  }

  /* Transfer the selected address info into ai */
  if(addr0) {
    memset(ai, 0, sizeof(*ai));
    ai->ai_family = addr0->ai_family;
    ai->ai_socktype = addr0->ai_socktype;
    ai->ai_protocol = addr0->ai_protocol;
    ai->ai_addrlen = addr0->ai_addrlen;
    ai->ai_canonname = addr0->ai_canonname;
    ai->ai_addr = addr0->ai_addr;
    return 1; /* success */
  }
  return 0; /* no address found */
}

CURLcode Curl_cf_h3_proxy_insert_after(struct Curl_cfilter **pcf,
                                       struct Curl_easy *data)
{
  struct Curl_cfilter *cf = NULL, *udp_cf = NULL;
  struct cf_h3_proxy_ctx *ctx;
  struct connectdata *conn = data->conn;
  struct Curl_addrinfo ai = {0};
  CURLcode result = CURLE_OUT_OF_MEMORY;
  int rv;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_h3_proxy, ctx);
  if(result)
    goto out;

  rv = Curl_get_QUIC_addr_info(*pcf, data, &ai);
  if(!rv)
    failf(data, "Failed to get QUIC UDP socket addr info");

  result = Curl_cf_udp_create(&udp_cf, data, conn, &ai, TRNSPRT_QUIC);
  if(result)
    goto out;

  cf->next = udp_cf;
  Curl_conn_cf_insert_after(*pcf, cf);

out:
  if(result) {
    if(udp_cf)
      Curl_conn_cf_discard_sub(cf, udp_cf, data, TRUE);
    Curl_safefree(cf);
    cf_h3_proxy_ctx_free(ctx);
  }
  return result;
}

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_PROXY && USE_NGHTTP3 */
