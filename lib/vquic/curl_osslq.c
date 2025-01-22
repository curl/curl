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

#if defined(USE_OPENSSL_QUIC) && defined(USE_NGHTTP3)

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
#include "vquic.h"
#include "vquic_int.h"
#include "vquic-tls.h"
#include "vtls/keylog.h"
#include "vtls/vtls.h"
#include "vtls/openssl.h"
#include "curl_osslq.h"

#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* A stream window is the maximum amount we need to buffer for
 * each active transfer. We use HTTP/3 flow control and only ACK
 * when we take things out of the buffer.
 * Chunk size is large enough to take a full DATA frame */
#define H3_STREAM_WINDOW_SIZE (128 * 1024)
#define H3_STREAM_CHUNK_SIZE   (16 * 1024)
/* The pool keeps spares around and half of a full stream window
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

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
typedef uint32_t sslerr_t;
#else
typedef unsigned long sslerr_t;
#endif


/* How to access `call_data` from a cf_osslq filter */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_osslq_ctx *)(cf)->ctx)->call_data

static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data);

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
#if defined(SSL_ERROR_WANT_ASYNC)
  case SSL_ERROR_WANT_ASYNC:
    return "SSL_ERROR_WANT_ASYNC";
#endif
#if defined(SSL_ERROR_WANT_ASYNC_JOB)
  case SSL_ERROR_WANT_ASYNC_JOB:
    return "SSL_ERROR_WANT_ASYNC_JOB";
#endif
#if defined(SSL_ERROR_WANT_EARLY)
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
  case AF_INET: {
    struct sockaddr_in * const sin =
      (struct sockaddr_in * const)(void *)&addr->curl_sa_addr;
    if(!BIO_ADDR_rawmake(ba, AF_INET, &sin->sin_addr,
                         sizeof(sin->sin_addr), sin->sin_port)) {
      goto out;
    }
    result = CURLE_OK;
    break;
  }
#ifdef USE_IPV6
  case AF_INET6: {
    struct sockaddr_in6 * const sin =
      (struct sockaddr_in6 * const)(void *)&addr->curl_sa_addr;
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

/* QUIC stream (not necessarily H3) */
struct cf_osslq_stream {
  curl_int64_t id;
  SSL *ssl;
  struct bufq recvbuf; /* QUIC war data recv buffer */
  BIT(recvd_eos);
  BIT(closed);
  BIT(reset);
  BIT(send_blocked);
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

struct cf_osslq_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
  struct cf_call_data call_data;
  struct cf_osslq_h3conn h3;
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct curltime first_byte_at;     /* when first byte was recvd */
  struct bufc_pool stream_bufcp;     /* chunk pool for streams */
  struct Curl_hash streams;          /* hash `data->mid` to `h3_stream_ctx` */
  size_t max_stream_window;          /* max flow window for one stream */
  uint64_t max_idle_ms;              /* max idle time for QUIC connection */
  SSL_POLL_ITEM *poll_items;         /* Array for polling on writable state */
  struct Curl_easy **curl_items;     /* Array of easy objs */
  size_t item_count;                 /* count of elements in poll/curl_items */
  BIT(initialized);
  BIT(got_first_byte);               /* if first byte was received */
  BIT(x509_store_setup);             /* if x509 store has been set up */
  BIT(protocol_shutdown);            /* QUIC connection is shut down */
  BIT(need_recv);                    /* QUIC connection needs to receive */
  BIT(need_send);                    /* QUIC connection needs to send */
};

static void h3_stream_hash_free(void *stream);

static void cf_osslq_ctx_init(struct cf_osslq_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  Curl_bufcp_init(&ctx->stream_bufcp, H3_STREAM_CHUNK_SIZE,
                  H3_STREAM_POOL_SPARES);
  Curl_hash_offt_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->poll_items = NULL;
  ctx->curl_items = NULL;
  ctx->item_count = 0;
  ctx->initialized = TRUE;
}

static void cf_osslq_ctx_free(struct cf_osslq_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_bufcp_free(&ctx->stream_bufcp);
    Curl_hash_clean(&ctx->streams);
    Curl_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
    free(ctx->poll_items);
    free(ctx->curl_items);
  }
  free(ctx);
}

static void cf_osslq_ctx_close(struct cf_osslq_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  cf_osslq_h3conn_cleanup(&ctx->h3);
  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
  ctx->call_data = save;
}

static CURLcode cf_osslq_shutdown(struct Curl_cfilter *cf,
                                  struct Curl_easy *data, bool *done)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;
  int rc;

  CF_DATA_SAVE(save, cf, data);

  if(cf->shutdown || ctx->protocol_shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;
  ctx->need_send = FALSE;
  ctx->need_recv = FALSE;

  rc = SSL_shutdown_ex(ctx->tls.ossl.ssl,
                       SSL_SHUTDOWN_FLAG_NO_BLOCK, NULL, 0);
  if(rc == 0) {  /* ongoing */
    CURL_TRC_CF(data, cf, "shutdown ongoing");
    ctx->need_recv = TRUE;
    goto out;
  }
  else if(rc == 1) {  /* done */
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
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_osslq_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  if(ctx && ctx->tls.ossl.ssl) {
    CURL_TRC_CF(data, cf, "cf_osslq_close()");
    if(!cf->shutdown && !ctx->protocol_shutdown) {
      /* last best effort, which OpenSSL calls a "rapid" shutdown. */
      SSL_shutdown_ex(ctx->tls.ossl.ssl,
                      (SSL_SHUTDOWN_FLAG_NO_BLOCK | SSL_SHUTDOWN_FLAG_RAPID),
                      NULL, 0);
    }
    cf_osslq_ctx_close(ctx);
  }

  cf->connected = FALSE;
  CF_DATA_RESTORE(cf, save);
}

static void cf_osslq_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  CURL_TRC_CF(data, cf, "destroy");
  if(ctx) {
    CURL_TRC_CF(data, cf, "cf_osslq_destroy()");
    if(ctx->tls.ossl.ssl)
      cf_osslq_ctx_close(ctx);
    cf_osslq_ctx_free(ctx);
  }
  cf->ctx = NULL;
  /* No CF_DATA_RESTORE(cf, save) possible */
  (void)save;
}

static CURLcode cf_osslq_h3conn_add_stream(struct cf_osslq_h3conn *h3,
                                           SSL *stream_ssl,
                                           struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)SSL_get_stream_id(stream_ssl);

  if(h3->remote_ctrl_n >= ARRAYSIZE(h3->remote_ctrl)) {
    /* rejected, we are full */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] rejecting remote stream",
                stream_id);
    SSL_free(stream_ssl);
    return CURLE_FAILED_INIT;
  }
  switch(SSL_get_stream_type(stream_ssl)) {
    case SSL_STREAM_TYPE_READ: {
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
                  " stream", stream_id);
      SSL_free(stream_ssl);
      return CURLE_FAILED_INIT;
  }
  return CURLE_OK;

}

static CURLcode cf_osslq_ssl_err(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 int detail, CURLcode def_result)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
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
#if defined(SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED)
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
    char extramsg[80]="";
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
  struct cf_osslq_ctx *ctx = cf->ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */

  return Curl_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}

/**
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  struct cf_osslq_stream s;
  struct bufq sendbuf;   /* h3 request body */
  struct bufq recvbuf;   /* h3 response body */
  struct h1_req_parser h1; /* h1 request parsing */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  size_t recv_buf_nonflow; /* buffered bytes, not counting for flow control */
  curl_uint64_t error3; /* HTTP/3 stream error code */
  curl_off_t upload_left; /* number of request bytes left to upload */
  curl_off_t download_recvd; /* number of response DATA bytes received */
  int status_code; /* HTTP status code */
  bool resp_hds_complete; /* we have a complete, final response */
  bool closed; /* TRUE on stream close */
  bool reset;  /* TRUE on stream reset */
  bool send_closed; /* stream is local closed */
  BIT(quic_flow_blocked); /* stream is blocked by QUIC flow control */
};

#define H3_STREAM_CTX(ctx,data)   ((struct h3_stream_ctx *)(\
            data? Curl_hash_offt_get(&(ctx)->streams, (data)->mid) : NULL))

static void h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
  cf_osslq_stream_cleanup(&stream->s);
  Curl_bufq_free(&stream->sendbuf);
  Curl_bufq_free(&stream->recvbuf);
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
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

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
                  H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  stream->sendbuf_len_in_flight = 0;
  /* on recv, we need a flexible buffer limit since we also write
   * headers to it that are not counted against the nghttp3 flow limits. */
  Curl_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                  H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
  stream->recv_buf_nonflow = 0;
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_hash_offt_set(&ctx->streams, data->mid, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  (void)cf;
  if(stream) {
    CURL_TRC_CF(data, cf, "[%"FMT_PRId64"] easy handle is done",
                stream->s.id);
    if(ctx->h3.conn && !stream->closed) {
      nghttp3_conn_shutdown_stream_read(ctx->h3.conn, stream->s.id);
      nghttp3_conn_close_stream(ctx->h3.conn, stream->s.id,
                                NGHTTP3_H3_REQUEST_CANCELLED);
      nghttp3_conn_set_stream_user_data(ctx->h3.conn, stream->s.id, NULL);
      stream->closed = TRUE;
    }

    Curl_hash_offt_remove(&ctx->streams, data->mid);
  }
}

static struct cf_osslq_stream *cf_osslq_get_qstream(struct Curl_cfilter *cf,
                                                    struct Curl_easy *data,
                                                    int64_t stream_id)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

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
    struct Curl_llist_node *e;
    DEBUGASSERT(data->multi);
    for(e = Curl_llist_head(&data->multi->process); e; e = Curl_node_next(e)) {
      struct Curl_easy *sdata = Curl_node_elem(e);
      if(sdata->conn != data->conn)
        continue;
      stream = H3_STREAM_CTX(ctx, sdata);
      if(stream && stream->s.id == stream_id) {
        return &stream->s;
      }
    }
  }
  return NULL;
}

static void h3_drain_stream(struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
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

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  if(!pause) {
    /* unpaused. make it run again right away */
    h3_drain_stream(cf, data);
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
  return CURLE_OK;
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_osslq_ctx *ctx = cf->ctx;
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
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] RESET: error %" FMT_PRIu64,
                stream->s.id, stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] CLOSED", stream->s.id);
  }
  h3_drain_stream(cf, data);
  return 0;
}

/*
 * write_resp_raw() copies response data in raw format to the `data`'s
  * receive buffer. If not enough space is available, it appends to the
 * `data`'s overflow buffer.
 */
static CURLcode write_resp_raw(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const void *mem, size_t memlen,
                               bool flow)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;
  ssize_t nwritten;

  (void)cf;
  if(!stream) {
    return CURLE_RECV_ERROR;
  }
  nwritten = Curl_bufq_write(&stream->recvbuf, mem, memlen, &result);
  if(nwritten < 0) {
    return result;
  }

  if(!flow)
    stream->recv_buf_nonflow += (size_t)nwritten;

  if((size_t)nwritten < memlen) {
    /* This MUST not happen. Our recbuf is dimensioned to hold the
     * full max_stream_window and then some for this very reason. */
    DEBUGASSERT(0);
    return CURLE_RECV_ERROR;
  }
  return result;
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t buflen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result;

  (void)conn;
  (void)stream3_id;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  result = write_resp_raw(cf, data, buf, buflen, TRUE);
  if(result) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] DATA len=%zu, ERROR %d",
                stream->s.id, buflen, result);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  stream->download_recvd += (curl_off_t)buflen;
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] DATA len=%zu, total=%zd",
              stream->s.id, buflen, stream->download_recvd);
  h3_drain_stream(cf, data);
  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

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
  struct cf_osslq_ctx *ctx = cf->ctx;
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
    char line[14]; /* status line is always 13 characters long */
    size_t ncopy;

    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)h3val.base, h3val.len);
    if(result)
      return -1;
    ncopy = msnprintf(line, sizeof(line), "HTTP/3 %03d \r\n",
                      stream->status_code);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] status: %s", stream_id, line);
    result = write_resp_raw(cf, data, line, ncopy, FALSE);
    if(result) {
      return -1;
    }
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] header: %.*s: %.*s",
                stream_id, (int)h3name.len, h3name.base,
                (int)h3val.len, h3val.base);
    result = write_resp_raw(cf, data, h3name.base, h3name.len, FALSE);
    if(result) {
      return -1;
    }
    result = write_resp_raw(cf, data, ": ", 2, FALSE);
    if(result) {
      return -1;
    }
    result = write_resp_raw(cf, data, h3val.base, h3val.len, FALSE);
    if(result) {
      return -1;
    }
    result = write_resp_raw(cf, data, "\r\n", 2, FALSE);
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
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)cf;

  if(!stream)
    return 0;
  /* add a CRLF only if we have received some headers */
  result = write_resp_raw(cf, data, "\r\n", 2, FALSE);
  if(result) {
    return -1;
  }

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] end_headers, status=%d",
              stream_id, stream->status_code);
  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }
  h3_drain_stream(cf, data);
  return 0;
}

static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
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
                              void *stream_user_data) {
  struct Curl_cfilter *cf = user_data;
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
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
cb_h3_read_req_body(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags, void *user_data,
                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_osslq_ctx *ctx = cf->ctx;
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
  struct cf_osslq_ctx *ctx = cf->ctx;
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
  NULL /* recv_settings */
};

static CURLcode cf_osslq_h3conn_init(struct cf_osslq_ctx *ctx, SSL *conn,
                                     void *user_data)
{
  struct cf_osslq_h3conn *h3 = &ctx->h3;
  CURLcode result;
  int rc;

  nghttp3_settings_default(&h3->settings);
  rc = nghttp3_conn_client_new(&h3->conn,
                               &ngh3_callbacks,
                               &h3->settings,
                               nghttp3_mem_default(),
                               user_data);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = cf_osslq_stream_open(&h3->s_ctrl, conn,
                                SSL_STREAM_FLAG_ADVANCE|SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  result = cf_osslq_stream_open(&h3->s_qpack_enc, conn,
                                SSL_STREAM_FLAG_ADVANCE|SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  result = cf_osslq_stream_open(&h3->s_qpack_dec, conn,
                                SSL_STREAM_FLAG_ADVANCE|SSL_STREAM_FLAG_UNI,
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

static CURLcode cf_osslq_ctx_start(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  CURLcode result;
  int rv;
  const struct Curl_sockaddr_ex *peer_addr = NULL;
  BIO *bio = NULL;
  BIO_ADDR *baddr = NULL;

  DEBUGASSERT(ctx->initialized);

#define H3_ALPN "\x2h3"
  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               H3_ALPN, sizeof(H3_ALPN) - 1,
                               NULL, NULL, NULL, NULL);
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

#ifdef SSL_VALUE_QUIC_IDLE_TIMEOUT
  /* Added in OpenSSL v3.3.x */
  if(!SSL_set_feature_request_uint(ctx->tls.ossl.ssl,
                                   SSL_VALUE_QUIC_IDLE_TIMEOUT,
                                   CURL_QUIC_MAX_IDLE_MS)) {
    CURL_TRC_CF(data, cf, "error setting idle timeout, ");
    result = CURLE_FAILED_INIT;
    goto out;
  }
#endif

  SSL_set_bio(ctx->tls.ossl.ssl, bio, bio);
  bio = NULL;
  SSL_set_connect_state(ctx->tls.ossl.ssl);
  SSL_set_incoming_stream_policy(ctx->tls.ossl.ssl,
                                 SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
  /* setup the H3 things on top of the QUIC connection */
  result = cf_osslq_h3conn_init(ctx, ctx->tls.ossl.ssl, cf);

out:
  if(bio)
    BIO_free(bio);
  if(baddr)
    BIO_ADDR_free(baddr);
  CURL_TRC_CF(data, cf, "QUIC tls init -> %d", result);
  return result;
}

struct h3_quic_recv_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct cf_osslq_stream *s;
};

static ssize_t h3_quic_recv(void *reader_ctx,
                            unsigned char *buf, size_t len,
                            CURLcode *err)
{
  struct h3_quic_recv_ctx *x = reader_ctx;
  size_t nread;
  int rv;

  *err = CURLE_OK;
  rv = SSL_read_ex(x->s->ssl, buf, len, &nread);
  if(rv <= 0) {
    int detail = SSL_get_error(x->s->ssl, rv);
    if(detail == SSL_ERROR_WANT_READ || detail == SSL_ERROR_WANT_WRITE) {
      *err = CURLE_AGAIN;
      return -1;
    }
    else if(detail == SSL_ERROR_ZERO_RETURN) {
      CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] h3_quic_recv -> EOS",
                  x->s->id);
      x->s->recvd_eos = TRUE;
      return 0;
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
      return 0;
    }
    else {
      *err = cf_osslq_ssl_err(x->cf, x->data, detail, CURLE_RECV_ERROR);
      return -1;
    }
  }
  return (ssize_t)nread;
}

static CURLcode cf_osslq_stream_recv(struct cf_osslq_stream *s,
                                     struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
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
        (total_recv_len < H3_STREAM_CHUNK_SIZE)) {
    if(Curl_bufq_is_empty(&s->recvbuf) && !s->recvd_eos) {
      while(!eagain && !s->recvd_eos && !Curl_bufq_is_full(&s->recvbuf)) {
        nread = Curl_bufq_sipn(&s->recvbuf, 0, h3_quic_recv, &x, &result);
        if(nread < 0) {
          if(result != CURLE_AGAIN)
            goto out;
          result = CURLE_OK;
          eagain = TRUE;
        }
      }
    }

    /* Forward what we have to nghttp3 */
    if(!Curl_bufq_is_empty(&s->recvbuf)) {
      const unsigned char *buf;
      size_t blen;

      while(Curl_bufq_peek(&s->recvbuf, &buf, &blen)) {
        nread = nghttp3_conn_read_stream(ctx->h3.conn, s->id,
                                         buf, blen, 0);
        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] forward %zu bytes "
                    "to nghttp3 -> %zd", s->id, blen, nread);
        if(nread < 0) {
          failf(data, "nghttp3_conn_read_stream(len=%zu) error: %s",
                blen, nghttp3_strerror((int)nread));
          result = CURLE_RECV_ERROR;
          goto out;
        }
        /* success, `nread` is the flow for QUIC to count as "consumed",
         * not sure how that will work with OpenSSL. Anyways, without error,
         * all data that we passed is not owned by nghttp3. */
        Curl_bufq_skip(&s->recvbuf, blen);
        total_recv_len += blen;
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
  if(result)
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_osslq_stream_recv -> %d",
                s->id, result);
  return result;
}

static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(!ctx->tls.ossl.ssl)
    goto out;

  ERR_clear_error();

  /* 1. Check for new incoming streams */
  while(1) {
    SSL *snew = SSL_accept_stream(ctx->tls.ossl.ssl,
                                  SSL_ACCEPT_STREAM_NO_BLOCK);
    if(!snew)
      break;

    (void)cf_osslq_h3conn_add_stream(&ctx->h3, snew, cf, data);
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
    struct Curl_llist_node *e;
    struct h3_stream_ctx *stream;
    /* PULL all open streams */
    DEBUGASSERT(data->multi);
    for(e = Curl_llist_head(&data->multi->process); e; e = Curl_node_next(e)) {
      struct Curl_easy *sdata = Curl_node_elem(e);
      if(sdata->conn == data->conn && CURL_WANT_RECV(sdata)) {
        stream = H3_STREAM_CTX(ctx, sdata);
        if(stream && !stream->closed &&
           !Curl_bufq_is_full(&stream->recvbuf)) {
          result = cf_osslq_stream_recv(&stream->s, cf, sdata);
          if(result)
            goto out;
        }
      }
    }
  }

out:
  CURL_TRC_CF(data, cf, "progress_ingress -> %d", result);
  return result;
}

/* Iterate over all streams and check if blocked can be unblocked */
static CURLcode cf_osslq_check_and_unblock(struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream;
  size_t poll_count = 0;
  size_t result_count = 0;
  size_t idx_count = 0;
  CURLcode res = CURLE_OK;
  struct timeval timeout;
  void *tmpptr;

  if(ctx->h3.conn) {
    struct Curl_llist_node *e;

    res = CURLE_OUT_OF_MEMORY;

    if(ctx->item_count < Curl_llist_count(&data->multi->process)) {
      ctx->item_count = 0;
      tmpptr = realloc(ctx->poll_items,
                       Curl_llist_count(&data->multi->process) *
                       sizeof(SSL_POLL_ITEM));
      if(!tmpptr) {
        free(ctx->poll_items);
        ctx->poll_items = NULL;
        goto out;
      }
      ctx->poll_items = tmpptr;

      tmpptr = realloc(ctx->curl_items,
                       Curl_llist_count(&data->multi->process) *
                       sizeof(struct Curl_easy *));
      if(!tmpptr) {
        free(ctx->curl_items);
        ctx->curl_items = NULL;
        goto out;
      }
      ctx->curl_items = tmpptr;

      ctx->item_count = Curl_llist_count(&data->multi->process);
    }

    for(e = Curl_llist_head(&data->multi->process); e; e = Curl_node_next(e)) {
      struct Curl_easy *sdata = Curl_node_elem(e);
      if(sdata->conn == data->conn) {
        stream = H3_STREAM_CTX(ctx, sdata);
        if(stream && stream->s.ssl && stream->s.send_blocked) {
          ctx->poll_items[poll_count].desc =
            SSL_as_poll_descriptor(stream->s.ssl);
          ctx->poll_items[poll_count].events = SSL_POLL_EVENT_W;
          ctx->curl_items[poll_count] = sdata;
          poll_count++;
        }
      }
    }

    memset(&timeout, 0, sizeof(struct timeval));
    res = CURLE_UNRECOVERABLE_POLL;
    if(!SSL_poll(ctx->poll_items, poll_count, sizeof(SSL_POLL_ITEM), &timeout,
                 0, &result_count))
        goto out;

    res = CURLE_OK;

    for(idx_count = 0; idx_count < poll_count && result_count > 0;
        idx_count++) {
      if(ctx->poll_items[idx_count].revents & SSL_POLL_EVENT_W) {
        stream = H3_STREAM_CTX(ctx, ctx->curl_items[idx_count]);
        nghttp3_conn_unblock_stream(ctx->h3.conn, stream->s.id);
        stream->s.send_blocked = FALSE;
        h3_drain_stream(cf, ctx->curl_items[idx_count]);
        CURL_TRC_CF(ctx->curl_items[idx_count], cf, "unblocked");
        result_count--;
      }
    }
  }

out:
  return res;
}

static CURLcode h3_send_streams(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
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
    for(i = 0, total_len = 0; i < n; ++i) {
      total_len += vec[i].len;
    }
    for(i = 0; (i < n) && !blocked; ++i) {
      /* Without stream->s.ssl, we closed that already, so
       * pretend the write did succeed. */
      uint64_t flags = (eos && ((i + 1) == n)) ? SSL_WRITE_FLAG_CONCLUDE : 0;
      written = vec[i].len;
      ok = !s->ssl || SSL_write_ex2(s->ssl, vec[i].base, vec[i].len, flags,
                                   &written);
      if(ok && flags & SSL_WRITE_FLAG_CONCLUDE)
        eos_written = TRUE;
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
          CURL_TRC_CF(data, cf, "[%"FMT_PRId64 "] send %zu bytes to "
                      "QUIC blocked", s->id, vec[i].len);
          written = 0;
          nghttp3_conn_block_stream(ctx->h3.conn, s->id);
          s->send_blocked = blocked = TRUE;
          break;
        default:
          failf(data, "[%"FMT_PRId64 "] send %zu bytes to QUIC, SSL error %d",
                s->id, vec[i].len, detail);
          result = cf_osslq_ssl_err(cf, data, detail, CURLE_HTTP3);
          goto out;
        }
      }
    }

    if(acked_len > 0 || (eos && !s->send_blocked)) {
      /* Since QUIC buffers the data written internally, we can tell
       * nghttp3 that it can move forward on it */
      ctx->q.last_io = Curl_now();
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
                  "to QUIC, eos=%d", s->id, acked_len, total_len, eos);
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

static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
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
  struct cf_osslq_ctx *ctx = cf->ctx;
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
      result = cf_progress_ingress(cf, data);
      if(result)
        goto out;
      result = cf_progress_egress(cf, data);
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

static CURLcode cf_osslq_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool blocking, bool *done)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  struct curltime now;
  int err;

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
  CF_DATA_SAVE(save, cf, data);

  if(!ctx->tls.ossl.ssl) {
    ctx->started_at = now;
    result = cf_osslq_ctx_start(cf, data);
    if(result)
      goto out;
  }

  if(!ctx->got_first_byte) {
    int readable = SOCKET_READABLE(ctx->q.sockfd, 0);
    if(readable > 0 && (readable & CURL_CSELECT_IN)) {
      ctx->got_first_byte = TRUE;
      ctx->first_byte_at = Curl_now();
    }
  }

  /* Since OpenSSL does its own send/recv internally, we may miss the
   * moment to populate the x509 store right before the server response.
   * Do it instead before we start the handshake, at the loss of the
   * time to set this up. */
  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    goto out;

  ERR_clear_error();
  err = SSL_do_handshake(ctx->tls.ossl.ssl);

  if(err == 1) {
    /* connected */
    ctx->handshake_at = now;
    ctx->q.last_io = now;
    CURL_TRC_CF(data, cf, "handshake complete after %dms",
               (int)Curl_timediff(now, ctx->started_at));
    result = cf_osslq_verify_peer(cf, data);
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }
  else {
    int detail = SSL_get_error(ctx->tls.ossl.ssl, err);
    switch(detail) {
    case SSL_ERROR_WANT_READ:
      ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_RECV");
      goto out;
    case SSL_ERROR_WANT_WRITE:
      ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_SEND");
      result = CURLE_OK;
      goto out;
#ifdef SSL_ERROR_WANT_ASYNC
    case SSL_ERROR_WANT_ASYNC:
      ctx->q.last_io = now;
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
  if(result == CURLE_RECV_ERROR && ctx->tls.ossl.ssl &&
     ctx->protocol_shutdown) {
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
  if(!result)
    result = check_and_set_expiry(cf, data);
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static ssize_t h3_stream_open(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const void *buf, size_t len,
                              CURLcode *err)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
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

  DEBUGASSERT(stream->s.id == -1);
  *err = cf_osslq_stream_open(&stream->s, ctx->tls.ossl.ssl, 0,
                              &ctx->stream_bufcp, data);
  if(*err) {
    failf(data, "cannot get bidi streams");
    *err = CURLE_SEND_ERROR;
    goto out;
  }

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

  rc = nghttp3_conn_submit_request(ctx->h3.conn, stream->s.id,
                                   nva, nheader, preader, data);
  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%"FMT_PRId64"] failed to send, "
                  "connection is closing", stream->s.id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%"FMT_PRId64 "] failed to send -> %d (%s)",
                  stream->s.id, rc, nghttp3_strerror(rc));
      break;
    }
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" FMT_PRId64 "] OPENED stream for %s",
          stream->s.id, data->state.url);
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" FMT_PRId64 "] [%.*s: %.*s]",
            stream->s.id,
            (int)nva[i].namelen, nva[i].name,
            (int)nva[i].valuelen, nva[i].value);
    }
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  return nwritten;
}

static ssize_t cf_osslq_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                             const void *buf, size_t len, bool eos,
                             CURLcode *err)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  ssize_t nwritten;
  CURLcode result;

  (void)eos; /* TODO: use to end stream */
  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->tls.ossl.ssl);
  DEBUGASSERT(ctx->h3.conn);
  *err = CURLE_OK;

  result = cf_progress_ingress(cf, data);
  if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }

  result = cf_progress_egress(cf, data);
  if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }

  if(!stream || stream->s.id < 0) {
    nwritten = h3_stream_open(cf, data, buf, len, err);
    if(nwritten < 0) {
      CURL_TRC_CF(data, cf, "failed to open stream -> %d", *err);
      goto out;
    }
    stream = H3_STREAM_CTX(ctx, data);
  }
  else if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] discarding data"
                  "on closed stream with response", stream->s.id);
      *err = CURLE_OK;
      nwritten = (ssize_t)len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send_body(len=%zu) "
                "-> stream closed", stream->s.id, len);
    *err = CURLE_HTTP3;
    nwritten = -1;
    goto out;
  }
  else {
    nwritten = Curl_bufq_write(&stream->sendbuf, buf, len, err);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send, add to "
                "sendbuf(len=%zu) -> %zd, %d",
                stream->s.id, len, nwritten, *err);
    if(nwritten < 0) {
      goto out;
    }

    (void)nghttp3_conn_resume_stream(ctx->h3.conn, stream->s.id);
  }

  result = cf_progress_egress(cf, data);
  if(result) {
    *err = result;
    nwritten = -1;
  }

out:
  result = check_and_set_expiry(cf, data);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send(len=%zu) -> %zd, %d",
              stream ? stream->s.id : -1, len, nwritten, *err);
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

static ssize_t recv_closed_stream(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream,
                                  CURLcode *err)
{
  ssize_t nread = -1;

  (void)cf;
  if(stream->reset) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64 " reset by server",
          stream->s.id);
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    goto out;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64
          " was closed cleanly, but before getting"
          " all response header fields, treated as error",
          stream->s.id);
    *err = CURLE_HTTP3;
    goto out;
  }
  *err = CURLE_OK;
  nread = 0;

out:
  return nread;
}

static ssize_t cf_osslq_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                             char *buf, size_t len, CURLcode *err)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nread = -1;
  struct cf_call_data save;
  CURLcode result;

  (void)ctx;
  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->tls.ossl.ssl);
  DEBUGASSERT(ctx->h3.conn);
  *err = CURLE_OK;

  if(!stream) {
    *err = CURLE_RECV_ERROR;
    goto out;
  }

  if(!Curl_bufq_is_empty(&stream->recvbuf)) {
    nread = Curl_bufq_read(&stream->recvbuf,
                           (unsigned char *)buf, len, err);
    if(nread < 0) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read recvbuf(len=%zu) "
                  "-> %zd, %d", stream->s.id, len, nread, *err);
      goto out;
    }
  }

  result = cf_progress_ingress(cf, data);
  if(result) {
    *err = result;
    nread = -1;
    goto out;
  }

  /* recvbuf had nothing before, maybe after progressing ingress? */
  if(nread < 0 && !Curl_bufq_is_empty(&stream->recvbuf)) {
    nread = Curl_bufq_read(&stream->recvbuf,
                           (unsigned char *)buf, len, err);
    if(nread < 0) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read recvbuf(len=%zu) "
                  "-> %zd, %d", stream->s.id, len, nread, *err);
      goto out;
    }
  }

  if(nread > 0) {
    h3_drain_stream(cf, data);
  }
  else {
    if(stream->closed) {
      nread = recv_closed_stream(cf, data, stream, err);
      goto out;
    }
    *err = CURLE_AGAIN;
    nread = -1;
  }

out:
  if(cf_progress_egress(cf, data)) {
    *err = CURLE_SEND_ERROR;
    nread = -1;
  }
  else {
    CURLcode result2 = check_and_set_expiry(cf, data);
    if(result2) {
      *err = result2;
      nread = -1;
    }
  }
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_recv(len=%zu) -> %zd, %d",
              stream ? stream->s.id : -1, len, nread, *err);
  CF_DATA_RESTORE(cf, save);
  return nread;
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
static bool cf_osslq_data_pending(struct Curl_cfilter *cf,
                                  const struct Curl_easy *data)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  const struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  return stream && !Curl_bufq_is_empty(&stream->recvbuf);
}

static CURLcode cf_osslq_data_event(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    int event, int arg1, void *arg2)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
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
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(stream && !stream->send_closed) {
      stream->send_closed = TRUE;
      stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
        stream->sendbuf_len_in_flight;
      (void)nghttp3_conn_resume_stream(ctx->h3.conn, stream->s.id);
    }
    break;
  }
  case CF_CTRL_DATA_IDLE: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    CURL_TRC_CF(data, cf, "data idle");
    if(stream && !stream->closed) {
      result = check_and_set_expiry(cf, data);
    }
    break;
  }
  default:
    break;
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}

static bool cf_osslq_conn_is_alive(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *input_pending)
{
  struct cf_osslq_ctx *ctx = cf->ctx;
  bool alive = FALSE;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
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
    idletime = Curl_timediff(Curl_now(), ctx->q.last_io);
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
    result = cf_progress_ingress(cf, data);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result ? FALSE : TRUE;
  }

out:
  CF_DATA_RESTORE(cf, save);
  return alive;
}

static void cf_osslq_adjust_pollset(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct easy_pollset *ps)
{
  struct cf_osslq_ctx *ctx = cf->ctx;

  if(!ctx->tls.ossl.ssl) {
    /* NOP */
  }
  else if(!cf->connected) {
    /* during handshake, transfer has not started yet. we always
     * add our socket for polling if SSL wants to send/recv */
    Curl_pollset_set(data, ps, ctx->q.sockfd,
                     SSL_net_read_desired(ctx->tls.ossl.ssl),
                     SSL_net_write_desired(ctx->tls.ossl.ssl));
  }
  else {
    /* once connected, we only modify the socket if it is present.
     * this avoids adding it for paused transfers. */
    bool want_recv, want_send;
    Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
    if(want_recv || want_send) {
      Curl_pollset_set(data, ps, ctx->q.sockfd,
                       SSL_net_read_desired(ctx->tls.ossl.ssl),
                       SSL_net_write_desired(ctx->tls.ossl.ssl));
    }
    else if(ctx->need_recv || ctx->need_send) {
      Curl_pollset_set(data, ps, ctx->q.sockfd,
                       ctx->need_recv, ctx->need_send);
    }
  }
}

static CURLcode cf_osslq_query(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               int query, int *pres1, void *pres2)
{
  struct cf_osslq_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
#ifdef SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL
    /* Added in OpenSSL v3.3.x */
    uint64_t v;
    if(!SSL_get_value_uint(ctx->tls.ossl.ssl, SSL_VALUE_CLASS_GENERIC,
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
      timediff_t ms = Curl_timediff(ctx->first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->got_first_byte)
      *when = ctx->first_byte_at;
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
  cf_osslq_destroy,
  cf_osslq_connect,
  cf_osslq_close,
  cf_osslq_shutdown,
  Curl_cf_def_get_host,
  cf_osslq_adjust_pollset,
  cf_osslq_data_pending,
  cf_osslq_send,
  cf_osslq_recv,
  cf_osslq_data_event,
  cf_osslq_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_osslq_query,
};

CURLcode Curl_cf_osslq_create(struct Curl_cfilter **pcf,
                              struct Curl_easy *data,
                              struct connectdata *conn,
                              const struct Curl_addrinfo *ai)
{
  struct cf_osslq_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL, *udp_cf = NULL;
  CURLcode result;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_osslq_ctx_init(ctx);

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
    cf_osslq_ctx_free(ctx);
  }
  return result;
}

bool Curl_conn_is_osslq(const struct Curl_easy *data,
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

/*
 * Store ngtcp2 version info in this buffer.
 */
void Curl_osslq_ver(char *p, size_t len)
{
  const nghttp3_info *ht3 = nghttp3_version(0);
  (void)msnprintf(p, len, "nghttp3/%s", ht3->version_str);
}

#endif /* USE_OPENSSL_QUIC && USE_NGHTTP3 */
