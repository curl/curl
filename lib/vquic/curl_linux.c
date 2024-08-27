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

#if defined(USE_LINUX_QUIC) && defined(USE_NGHTTP3)
#include <linux/tls.h>
#include <linux/quic.h>
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
#include "transfer.h"
#include "vtls/gtls.h"
#include "vquic.h"
#include "vquic_int.h"
#include "vquic-tls.h"
#include "vtls/keylog.h"
#include "vtls/vtls.h"
#include "curl_linux.h"

#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


void Curl_linuxq_ver(char *p, size_t len)
{
  const nghttp3_info *ht3 = nghttp3_version(0);
  (void)msnprintf(p, len, "linuxq nghttp3/%s", ht3->version_str);
}

struct linuxq_conn {
  BIT(completed);             /* TLS handshaked completed */
};

struct cf_linuxq_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
  struct linuxq_conn *qconn;
  uint32_t version;
  uint32_t last_error;
  struct quic_transport_param transport_params;
  struct cf_call_data call_data;
  nghttp3_conn *h3conn;
  nghttp3_settings h3settings;
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct curltime reconnect_at;      /* time the next attempt should start */
  struct dynbuf scratch;             /* temp buffer for header construction */
  struct Curl_hash streams;          /* hash `data->id` to `h3_stream_ctx` */
  uint64_t used_bidi_streams;        /* bidi streams we have opened */
  uint64_t max_bidi_streams;         /* max bidi streams we can open */
  BIT(shutdown_started);             /* queued shutdown packets */
};

/* How to access `call_data` from a cf_linuxq filter */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_linuxq_ctx *)(cf)->ctx)->call_data

static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data);
static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data);

/**
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  curl_int64_t id; /* HTTP/3 protocol identifier */
  struct h1_req_parser h1; /* h1 request parsing */
  size_t upload_blocked_len; /* the amount written last and EGAINed */
  curl_uint64_t error3; /* HTTP/3 stream error code */
  curl_off_t upload_left; /* number of request bytes left to upload */
  int status_code; /* HTTP status code */
  CURLcode xfer_result; /* result from xfer_resp_write(_hd) */
  bool resp_hds_complete; /* we have a complete, final response */
  bool closed; /* TRUE on stream close */
  bool reset;  /* TRUE on stream reset */
  bool send_closed; /* stream is local closed */
};

#define H3_STREAM_CTX(ctx,data)   ((struct h3_stream_ctx *)(\
            data? Curl_hash_offt_get(&(ctx)->streams, (data)->id) : NULL))
#define H3_STREAM_CTX_ID(ctx,id)  ((struct h3_stream_ctx *)(\
            Curl_hash_offt_get(&(ctx)->streams, (id))))

static int crypto_set_secret(struct cf_linuxq_ctx *ctx, uint8_t level,
                             uint32_t type, const uint8_t *rx_secret,
                             const uint8_t *tx_secret, size_t len)
{
  struct quic_crypto_secret secret = {0};
  int rc;
  DEBUGASSERT(len == 48);

  secret.level = level;
  secret.type = type;

  if(tx_secret) {
    secret.send = 1;
    memcpy(secret.secret, tx_secret, len);
    rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET,
                    &secret, sizeof(secret));
    if(rc)
      return -1;
  }

  if(rx_secret) {
    secret.send = 0;
    memcpy(secret.secret, rx_secret, len);
    rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET,
                    &secret, sizeof(secret));
    if(rc)
      return -1;

    if(secret.level == QUIC_CRYPTO_APP)
      ctx->qconn->completed = 1; /* XXX: make sure tx_secret is installed */
  }

  return 0;
}

static int crypto_send(struct cf_linuxq_ctx *ctx, const uint8_t *data,
                       uint32_t len, uint8_t level)
{
  struct quic_handshake_info *hsinfo;
  struct cmsghdr *cm;
  struct msghdr msg = {0};
  struct iovec vec;
  ssize_t n;
  uint8_t msg_ctrl[CMSG_SPACE(sizeof(struct quic_handshake_info))];

  vec.iov_base = (void *)data;
  vec.iov_len = len;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = msg_ctrl;
  msg.msg_controllen = sizeof(msg_ctrl);
  cm = CMSG_FIRSTHDR(&msg);
  cm->cmsg_level = IPPROTO_QUIC;
  cm->cmsg_type = QUIC_HANDSHAKE_INFO;
  cm->cmsg_len = CMSG_LEN(sizeof(*hsinfo));
  hsinfo = (struct quic_handshake_info *)CMSG_DATA(cm);
  hsinfo->crypto_level = level;

  n = sendmsg(ctx->q.sockfd, &msg, 0);
  if(n < 0)
    return -1;

  return 0;
}

#if defined(USE_OPENSSL)
static uint8_t crypto_ssl_level(enum ssl_encryption_level_t level)
{
  switch(level) {
  case ssl_encryption_application:
    return QUIC_CRYPTO_APP;
  case ssl_encryption_initial:
    return QUIC_CRYPTO_INITIAL;
  case ssl_encryption_handshake:
    return QUIC_CRYPTO_HANDSHAKE;
  case ssl_encryption_early_data:
    return QUIC_CRYPTO_EARLY;
  default:
    DEBUGASSERT(0);
    return QUIC_CRYPTO_MAX;
  }
}

static enum ssl_encryption_level_t crypto_to_ssl_level(uint8_t level)
{
  switch(level) {
  case QUIC_CRYPTO_APP:
    return ssl_encryption_application;
  case QUIC_CRYPTO_INITIAL:
    return ssl_encryption_initial;
  case QUIC_CRYPTO_HANDSHAKE:
    return ssl_encryption_handshake;
  case QUIC_CRYPTO_EARLY:
    return ssl_encryption_early_data;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}

static uint32_t crypto_ssl_cipher_type(uint32_t cipher)
{
  switch(cipher) {
#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return TLS_CIPHER_AES_CCM_128;
#endif
  case TLS1_3_CK_AES_128_GCM_SHA256:
    return TLS_CIPHER_AES_GCM_128;
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return TLS_CIPHER_AES_GCM_256;
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return TLS_CIPHER_CHACHA20_POLY1305;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}

static int crypto_ssl_set_secret(SSL *ssl,
                                 enum ssl_encryption_level_t ssl_level,
                                 const uint8_t *rx_secret,
                                 const uint8_t *tx_secret, size_t len)
{
  struct Curl_cfilter *cf = SSL_get_app_data(ssl);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  uint32_t type, ssl_type;
  int rc;
  uint8_t level;

  if(level == QUIC_CRYPTO_APP && rx_secret) {
    const uint8_t *extbuf;
    size_t extlen;

    SSL_get_peer_quic_transport_params(ssl, &extbuf, &extlen);
    rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
                    extbuf, extlen);
    if(rc)
      return 0;
  }

  if(!cipher)
    return 0;

  ssl_type = SSL_CIPHER_get_id(cipher);
  level = crypto_ssl_level(ssl_level);
  type = crypto_ssl_cipher_type(ssl_type);
  rc = crypto_set_secret(ctx, level, type, rx_secret, tx_secret, len);

  if(rc < 0)
    return 0;

  return 1;
}

static int crypto_ssl_send(SSL *ssl, enum ssl_encryption_level_t ssl_level,
                           const uint8_t *data, size_t len)
{
  struct Curl_cfilter *cf = SSL_get_app_data(ssl);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  int rc;
  uint8_t level;

  level = crypto_ssl_level(ssl_level);
  rc = crypto_send(ctx, data, len, level);
  if(rc < 0)
    return 0;

  return 1;
}

static int crypto_ssl_flush(SSL *ssl)
{
  (void)ssl;
  return 1;
}

static int crypto_ssl_alert(SSL *ssl,
                            enum ssl_encryption_level_t ssl_level,
                            uint8_t alert)
{
  (void)ssl;
  (void)ssl_level;
  (void)alert;
  /* XXX: log, set alert */
  return 1;
}

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
static int crypto_bossl_set_rx_secret(SSL *ssl,
                                      enum ssl_encryption_level_t bossl_level,
                                      const SSL_CIPHER *cipher,
                                      const uint8_t *rx_secret, size_t len)
{
  /* XXX is cipher the same as SSL_get_current_cipher(ssl)? */
  return crypto_ssl_set_secret(ssl, bossl_level, rx_secret, NULL, len);
}

static int crypto_bossl_set_tx_secret(SSL *ssl,
                                      enum ssl_encryption_level_t bossl_level,
                                      const SSL_CIPHER *cipher,
                                      const uint8_t *tx_secret, size_t len)
{
  /* XXX is cipher the same as SSL_get_current_cipher(ssl)? */
  return crypto_ssl_set_secret(ssl, bossl_level, NULL, tx_secret, len);
}

static SSL_QUIC_METHOD crypto_ssl_quic_method = {
  crypto_bossl_set_rx_secret, crypto_bossl_set_tx_secret, crypto_ssl_send,
  crypto_ssl_flush, crypto_ssl_alert
};
#else
static SSL_QUIC_METHOD crypto_ssl_quic_method = {
  crypto_ssl_set_secret, crypto_ssl_send, crypto_ssl_flush, crypto_ssl_alert
#ifdef LIBRESSL_VERSION_NUMBER
  , NULL, NULL
#endif
};
#endif /* !OPENSSL_IS_BORINGSSL && !OPENSSL_IS_AWSLC */

static void crypto_ssl_configure_context(SSL_CTX *ssl_ctx)
{
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_quic_method(ssl_ctx, &crypto_ssl_quic_method);
}

static CURLcode crypto_ssl_do_handshake(struct Curl_cfilter *cf,
                                        struct Curl_easy *data, uint8_t level,
                                        const uint8_t *buf, size_t len)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  SSL *ssl = ctx->tls.ossl.ssl;
  enum ssl_encryption_level_t ssl_level;
  int rc;

  if(len > 0) {
    ssl_level = crypto_to_ssl_level(level);
    rc = SSL_provide_quic_data(ssl, ssl_level, buf, len);
    if(rc != 1) {
      failf(data, "SSL_provide_quic_data failed");
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }
  else if(level == QUIC_CRYPTO_INITIAL) {
    uint8_t extbuf[256];
    socklen_t extlen = sizeof(extbuf);
    rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
                    extbuf, &extlen);
    if(rc)
      return CURLE_QUIC_CONNECT_ERROR;

    if(SSL_set_quic_transport_params(ssl, extbuf, extlen) != 1)
      return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = SSL_do_handshake(ssl);
  if(rc <= 0) {
    rc = SSL_get_error(ssl, rc);
    if(rc != SSL_ERROR_WANT_READ && rc != SSL_ERROR_WANT_WRITE) {
      failf(data, "SSL_do_handshake: SSL_get_error: %d", rc);
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }

  if(ctx->qconn->completed) {
    rc = SSL_process_quic_post_handshake(ssl);
    if(rc != 1)
      return CURLE_QUIC_CONNECT_ERROR;
  }

  return CURLE_OK;
}

#elif defined(USE_GNUTLS)
static int crypto_gtls_alert(gnutls_session_t session,
                             gnutls_record_encryption_level_t gtls_level,
                             gnutls_alert_level_t alert_level,
                             gnutls_alert_description_t alert)
{
  (void)session;
  (void)gtls_level;
  (void)alert_level;
  (void)alert;
  /* XXX: log, set alert */
  return 0;
}

static uint8_t crypto_gtls_level(gnutls_record_encryption_level_t level)
{
  switch(level) {
  case GNUTLS_ENCRYPTION_LEVEL_APPLICATION:
    return QUIC_CRYPTO_APP;
  case GNUTLS_ENCRYPTION_LEVEL_INITIAL:
    return QUIC_CRYPTO_INITIAL;
  case GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE:
    return QUIC_CRYPTO_HANDSHAKE;
  case GNUTLS_ENCRYPTION_LEVEL_EARLY:
    return QUIC_CRYPTO_EARLY;
  default:
    DEBUGASSERT(0);
    return QUIC_CRYPTO_MAX;
  }
}

static gnutls_record_encryption_level_t crypto_to_gtls_level(uint8_t level)
{
  switch(level) {
  case QUIC_CRYPTO_APP:
    return GNUTLS_ENCRYPTION_LEVEL_APPLICATION;
  case QUIC_CRYPTO_INITIAL:
    return GNUTLS_ENCRYPTION_LEVEL_INITIAL;
  case QUIC_CRYPTO_HANDSHAKE:
    return GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE;
  case QUIC_CRYPTO_EARLY:
    return GNUTLS_ENCRYPTION_LEVEL_EARLY;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}

static int crypto_gtls_send(gnutls_session_t session,
                            gnutls_record_encryption_level_t gtls_level,
                            gnutls_handshake_description_t htype,
                            const void *data, size_t len)
{
  struct Curl_cfilter *cf = gnutls_session_get_ptr(session);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  int rc;
  uint8_t level;

  if(htype == GNUTLS_HANDSHAKE_KEY_UPDATE ||
      htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
    return 0;

  level = crypto_gtls_level(gtls_level);
  rc = crypto_send(ctx, data, len, level);
  return rc;
}

static uint32_t crypto_gtls_cipher_type(gnutls_cipher_algorithm_t cipher)
{
  switch(cipher) {
  case GNUTLS_CIPHER_AES_128_CCM:
    return TLS_CIPHER_AES_CCM_128;
  case GNUTLS_CIPHER_AES_128_GCM:
    return TLS_CIPHER_AES_GCM_128;
  case GNUTLS_CIPHER_AES_256_GCM:
    return TLS_CIPHER_AES_GCM_256;
  case GNUTLS_CIPHER_CHACHA20_POLY1305:
    return TLS_CIPHER_CHACHA20_POLY1305;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}

static int crypto_gtls_set_secret(gnutls_session_t session,
                                  gnutls_record_encryption_level_t gtls_level,
                                  const void *rx_secret, const void *tx_secret,
                                  size_t len)
{
  struct Curl_cfilter *cf = gnutls_session_get_ptr(session);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  gnutls_cipher_algorithm_t gtls_type = gnutls_cipher_get(session);
  uint32_t type;
  int rc;
  uint8_t level;

  if(ctx->qconn->completed)
    return 0;

  if(gtls_level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
    gtls_type = gnutls_early_cipher_get(session);

  level = crypto_gtls_level(gtls_level);
  type = crypto_gtls_cipher_type(gtls_type);
  rc = crypto_set_secret(ctx, level, type, rx_secret, tx_secret, len);
  return rc;
}

static int crypto_gtls_tp_tx(gnutls_session_t session, gnutls_buffer_t data)
{
  struct Curl_cfilter *cf = gnutls_session_get_ptr(session);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  uint8_t buf[256];
  socklen_t len = sizeof(buf);
  int rc;

  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
                  buf, &len);
  if(rc)
    return -1;

  rc = gnutls_buffer_append_data(data, buf, len);

  return rc;
}

static int crypto_gtls_tp_rx(gnutls_session_t session, const uint8_t *data,
                             size_t len)
{
  struct Curl_cfilter *cf = gnutls_session_get_ptr(session);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  int rc;

  rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
                  data, len);
  return rc;
}

static int crypto_gtls_configure_session(gnutls_session_t session)
{
  int rv;

  gnutls_alert_set_read_function(session, crypto_gtls_alert);
  gnutls_handshake_set_read_function(session, crypto_gtls_send);
  gnutls_handshake_set_secret_function(session, crypto_gtls_set_secret);

  rv = gnutls_session_ext_register(session, "QUIC Transport Parameters", 0x39,
                                   GNUTLS_EXT_TLS, crypto_gtls_tp_rx,
                                   crypto_gtls_tp_tx, NULL, NULL, NULL,
                                   GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_EE |
                                   GNUTLS_EXT_FLAG_CLIENT_HELLO);
  return rv;
}

static CURLcode crypto_gtls_do_handshake(struct Curl_cfilter *cf,
                                         struct Curl_easy *data, uint8_t level,
                                         const uint8_t *buf, size_t len)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  gnutls_session_t session;
  gnutls_record_encryption_level_t gtls_level;
  int rc;

  session = ctx->tls.gtls.session;
  if(len > 0) {
    gtls_level = crypto_to_gtls_level(level);
    rc = gnutls_handshake_write(session, gtls_level, buf, len);
    if(rc) {
      if(gnutls_error_is_fatal(rc)) {
        gnutls_alert_send_appropriate(session, rc);
        failf(data, "gnutls_handshake_write failed");
        return CURLE_QUIC_CONNECT_ERROR;
      }
      else
        return CURLE_OK;
    }
  }

  rc = gnutls_handshake(session);
  if(rc < 0) {
    if(gnutls_error_is_fatal(rc)) {
      gnutls_alert_send_appropriate(session, rc);
      failf(data, "gnutls_handshake failed");
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }
  return CURLE_OK;
}

#elif defined(USE_WOLFSSL)
static uint8_t crypto_wssl_level(WOLFSSL_ENCRYPTION_LEVEL level)
{
  switch(level) {
  case wolfssl_encryption_application:
    return QUIC_CRYPTO_APP;
  case wolfssl_encryption_initial:
    return QUIC_CRYPTO_INITIAL;
  case wolfssl_encryption_handshake:
    return QUIC_CRYPTO_HANDSHAKE;
  case wolfssl_encryption_early_data:
    return QUIC_CRYPTO_EARLY;
  default:
    DEBUGASSERT(0);
    return QUIC_CRYPTO_MAX;
  }
}

static WOLFSSL_ENCRYPTION_LEVEL crypto_to_wssl_level(uint8_t level)
{
  switch(level) {
  case QUIC_CRYPTO_APP:
    return wolfssl_encryption_application;
  case QUIC_CRYPTO_INITIAL:
    return wolfssl_encryption_initial;
  case QUIC_CRYPTO_HANDSHAKE:
    return wolfssl_encryption_handshake;
  case QUIC_CRYPTO_EARLY:
    return wolfssl_encryption_early_data;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}

static uint32_t crypto_wssl_cipher_type(uint32_t cipher)
{
  switch(cipher) {
  case TLS1_3_CK_AES_128_CCM_SHA256:
    return TLS_CIPHER_AES_CCM_128;
  case TLS1_3_CK_AES_128_GCM_SHA256:
    return TLS_CIPHER_AES_GCM_128;
  case TLS1_3_CK_AES_256_GCM_SHA384:
    return TLS_CIPHER_AES_GCM_256;
  case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    return TLS_CIPHER_CHACHA20_POLY1305;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}

static int crypto_wssl_set_secret(WOLFSSL *wssl,
                                  WOLFSSL_ENCRYPTION_LEVEL wssl_level,
                                  const uint8_t *rx_secret,
                                  const uint8_t *tx_secret, size_t len)
{
  struct Curl_cfilter *cf = wolfSSL_get_app_data(wssl);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  const WOLFSSL_CIPHER *cipher = wolfSSL_get_current_cipher(wssl);
  uint32_t type, wssl_type;
  int rc;
  uint8_t level;

  if(level == QUIC_CRYPTO_APP && rx_secret) {
    const uint8_t *extbuf;
    size_t extlen;

    wolfSSL_get_peer_quic_transport_params(wssl, &extbuf, &extlen);
    rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
                    extbuf, extlen);
    if(rc)
      return 0;
  }

  if(!cipher)
    return 0;

  wssl_type = wolfSSL_CIPHER_get_id(cipher);
  level = crypto_wssl_level(wssl_level);
  type = crypto_wssl_cipher_type(wssl_type);
  rc = crypto_set_secret(ctx, level, type, rx_secret, tx_secret, len);

  if(rc < 0)
    return 0;

  return 1;
}

static int crypto_wssl_send(WOLFSSL *wssl, WOLFSSL_ENCRYPTION_LEVEL wssl_level,
                            const uint8_t *data, size_t len)
{
  struct Curl_cfilter *cf = wolfSSL_get_app_data(wssl);
  struct cf_linuxq_ctx *ctx = cf->ctx;
  int rc;
  uint8_t level;

  level = crypto_wssl_level(wssl_level);
  rc = crypto_send(ctx, data, len, level);
  if(rc < 0)
    return 0;

  return 1;
}

static int crypto_wssl_flush(WOLFSSL *wssl)
{
  (void)wssl;
  return 1;
}

static int crypto_wssl_alert(WOLFSSL *wssl,
                             WOLFSSL_ENCRYPTION_LEVEL wssl_level,
                             uint8_t alert)
{
  (void)wssl;
  (void)wssl_level;
  (void)alert;
  /* XXX: log, set alert */
  return 1;
}

static WOLFSSL_QUIC_METHOD crypto_wssl_quic_method = {
  crypto_wssl_set_secret, crypto_wssl_send, crypto_wssl_flush,
  crypto_wssl_alert
};

static void crypto_wssl_configure_context(WOLFSSL_CTX *wssl_ctx)
{
  wolfSSL_CTX_set_max_proto_version(wssl_ctx, TLS1_3_VERSION);
  wolfSSL_CTX_set_min_proto_version(wssl_ctx, TLS1_3_VERSION);
  wolfSSL_CTX_set_quic_method(wssl_ctx, &crypto_wssl_quic_method);
}

static CURLcode crypto_wssl_do_handshake(struct Curl_cfilter *cf,
                                        struct Curl_easy *data, uint8_t level,
                                        const uint8_t *buf, size_t len)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  WOLFSSL *wssl = ctx->tls.wssl.handle;
  WOLFSSL_ENCRYPTION_LEVEL wssl_level;
  int rc;

  if(len > 0) {
    wssl_level = crypto_to_wssl_level(level);
    rc = wolfSSL_provide_quic_data(wssl, wssl_level, buf, len);
    if(rc != 1) {
      failf(data, "wolfSSL_provide_quic_data failed");
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }
  else if(level == QUIC_CRYPTO_INITIAL) {
    uint8_t extbuf[256];
    socklen_t extlen = sizeof(extbuf);
    rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
                    extbuf, &extlen);
    if(rc)
      return CURLE_QUIC_CONNECT_ERROR;

    if(wolfSSL_set_quic_transport_params(wssl, extbuf, extlen) != 1)
      return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = wolfSSL_SSL_do_handshake(wssl);
  if(rc <= 0) {
    rc = wolfSSL_get_error(wssl, rc);
    if(rc != WOLFSSL_ERROR_WANT_READ && rc != WOLFSSL_ERROR_WANT_WRITE) {
      failf(data, "wolfSSL_do_handshake: wolfSSL_get_error: %d", rc);
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }

  if(ctx->qconn->completed) {
    rc = wolfSSL_process_quic_post_handshake(wssl);
    if(rc != 1)
      return CURLE_QUIC_CONNECT_ERROR;
  }

  return CURLE_OK;
}
#endif

static CURLcode crypto_do_handshake(struct Curl_cfilter *cf,
                                    struct Curl_easy *data, uint8_t level,
                                    const uint8_t *buf, size_t len)
{
  int rc;
#if defined(USE_OPENSSL)
  rc = crypto_ssl_do_handshake(cf, data, level, buf, len);
#elif defined(USE_GNUTLS)
  rc = crypto_gtls_do_handshake(cf, data, level, buf, len);
#elif defined(USE_WOLFSSL)
  rc = crypto_wssl_do_handshake(cf, data, level, buf, len);
#endif
  return rc;
}
static ssize_t crypto_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                            uint8_t *level, uint8_t *buf, unsigned int len)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct cf_quic_ctx *qctx = &ctx->q;
  struct quic_handshake_info hsinfo;
  struct msghdr msg;
  struct iovec msg_iov;
  struct cmsghdr *cm;
  ssize_t nread;
  char errstr[STRERROR_LEN];
  CURLcode result;
  uint8_t msg_ctrl[CMSG_SPACE(sizeof(struct quic_stream_info))];
  fd_set readfds;
  int rc;

  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    return -1;

  msg_iov.iov_base = buf;
  msg_iov.iov_len = len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;
  msg.msg_control = msg_ctrl;
  msg.msg_controllen = sizeof(msg_ctrl);

  FD_ZERO(&readfds);
  FD_SET(qctx->sockfd, &readfds);
  rc = select(qctx->sockfd + 1, &readfds, NULL,  NULL, NULL);
  if(rc < 0)
    return -1;
  nread = recvmsg(qctx->sockfd, &msg, 0);
  if(nread == -1) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK)
      goto out;
    if(!cf->connected && SOCKERRNO == ECONNREFUSED) {
      struct ip_quadruple ip;
      Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
      failf(data, "QUIC: connection to %s port %u refused",
            ip.remote_ip, ip.remote_port);
      goto out;
    }
    Curl_strerror(SOCKERRNO, errstr, sizeof(errstr));
    failf(data, "QUIC: recvmsg() unexpectedly returned %zd (errno=%d; %s)",
                nread, SOCKERRNO, errstr);
    goto out;
  }

  for(cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm))
    if(cm->cmsg_len == CMSG_LEN(sizeof(struct quic_handshake_info)) &&
       cm->cmsg_level == IPPROTO_QUIC && cm->cmsg_type == QUIC_HANDSHAKE_INFO)
      break;
  if(cm) {
    memcpy(&hsinfo, CMSG_DATA(cm), sizeof(hsinfo));
    *level = hsinfo.crypto_level;
    goto out;
  }
  else
    nread = -1;

  CURL_TRC_CF(data, cf, "recvd 1 packet with %zd bytes", nread);
out:
  return nread;
}

static CURLcode crypto_handshake(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  size_t len = 0;
  int rc;
  uint8_t buf[1200];
  uint8_t level = QUIC_CRYPTO_INITIAL;

  while(!ctx->qconn->completed) {
    rc = crypto_do_handshake(cf, data, level, buf, len);
    if(rc)
      return rc;
    if(ctx->qconn->completed)
      return 0;

    rc = crypto_recv(cf, data, &level, buf, sizeof(buf));
    if(rc < 0)
      return rc;
    len = rc;
  }
}


static void h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
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
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(!data) {
    /* XXX: data == NULL */
    failf(data, "initialization failure, transfer not http initialized");
    return CURLE_FAILED_INIT;
  }

  if(stream)
    return CURLE_OK;

  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  /* on send, we control how much we put into the buffer */
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_hash_offt_set(&ctx->streams, data->id, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void cf_linuxq_stream_close(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_stream_ctx *stream)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct quic_errinfo einfo;

  DEBUGASSERT(data);
  DEBUGASSERT(stream);
  if(!stream->closed && ctx->qconn && ctx->h3conn) {
    CURLcode result;

    nghttp3_conn_set_stream_user_data(ctx->h3conn, stream->id, NULL);
    stream->closed = TRUE;

    einfo.stream_id = (uint64_t)stream->id;
    einfo.errcode = (uint32_t)NGHTTP3_H3_REQUEST_CANCELLED;
    (void)setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET,
                     &einfo, sizeof(einfo));

    result = cf_progress_egress(cf, data);
    if(result)
      CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] cancel stream -> %d",
                  stream->id, result);
  }
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  if(stream) {
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] easy handle is done",
                stream->id);
    cf_linuxq_stream_close(cf, data, stream);
    Curl_hash_offt_remove(&ctx->streams, data->id);
  }
}

static void h3_drain_stream(struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
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

static CURLcode cf_linuxq_recv_stream_data(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           const uint8_t *buf, size_t buflen,
                                           int64_t sid, uint32_t flags)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  nghttp3_ssize nconsumed;
  int fin = (flags & MSG_STREAM_FIN) ? 1 : 0;
  (void)data;

  nconsumed =
    nghttp3_conn_read_stream(ctx->h3conn, stream_id, buf, buflen, fin);
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(data)
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] read_stream(len=%zu) -> %zd",
                stream_id, buflen, nconsumed);
  if(nconsumed < 0) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX_ID(ctx, stream_id);
    if(data && stream) {
      CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] error on known stream, "
                  "reset=%d, closed=%d",
                  stream_id, stream->reset, stream->closed);
    }
    if(nconsumed ==  NGHTTP3_ERR_NOMEM)
      return CURLE_OUT_OF_MEMORY;
    else
      return CURLE_HTTP3;
  }

  return CURLE_OK;
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
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
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] RESET: error %" CURL_PRIu64,
                stream->id, stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] CLOSED", stream->id);
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
      CURL_TRC_CF(data, cf, "[%"CURL_PRId64"] error %d writing %zu "
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
      CURL_TRC_CF(data, cf, "[%"CURL_PRId64"] error %d writing %zu bytes "
                  "of data", stream->id, stream->xfer_result, blen);
    }
  }
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t blen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  (void)conn;
  (void)stream3_id;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  h3_xfer_write_resp(cf, data, stream, (char *)buf, blen, FALSE);
  CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] DATA len=%zu", stream->id, blen);
  return 0;
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t len, void *user_data,
                                void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  int rv;

  (void)len;

  if(!stream)
    return 0;

  rv = nghttp3_conn_resume_stream(conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t sid,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
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

  CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] end_headers, status=%d",
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
  struct cf_linuxq_ctx *ctx = cf->ctx;
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
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] status: %s",
                stream_id, Curl_dyn_ptr(&ctx->scratch));
    if(result) {
      return -1;
    }
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] header: %.*s: %.*s",
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
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct quic_errinfo einfo;
  int rv;
  (void)conn;
  (void)stream_user_data;

  einfo.stream_id = (uint64_t)stream_id;
  einfo.errcode = (uint32_t)app_error_code;
  rv = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_STOP_SENDING,
                  &einfo, sizeof(einfo));
  if(rv == -1 && errno != EINVAL)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  return 0;
}

static int cb_h3_end_stream(nghttp3_conn *conn, int64_t stream_id,
                            void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;

  stream->closed = TRUE;
  h3_drain_stream(cf, data);

  return 0;
}

static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct quic_errinfo einfo;
  int rv;
  (void)conn;
  (void)data;

  einfo.stream_id = (uint64_t)stream_id;
  einfo.errcode = (uint32_t)app_error_code;
  rv = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &einfo,
                  sizeof(einfo));
  CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] reset -> %d", stream_id, rv);
  if(rv == -1 && errno != EINVAL)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  return 0;
}

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  NULL, /* cb_h3_deferred_consume */
  NULL, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  NULL, /* begin_trailers */
  cb_h3_recv_header,
  NULL, /* end_trailers */
  cb_h3_stop_sending,
  cb_h3_end_stream, /* end_stream */
  cb_h3_reset_stream,
  NULL, /* shutdown */
  NULL /* recv_settings */
};

static CURLcode init_ngh3_conn(struct Curl_cfilter *cf)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  CURLcode result;
  int rc;
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
  struct quic_stream_info sinfo;
  socklen_t len = sizeof(sinfo);

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

  sinfo.stream_id = -1;
  sinfo.stream_flags = MSG_STREAM_UNI;
  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo,
                  &len);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }
  ctrl_stream_id = sinfo.stream_id;

  rc = nghttp3_conn_bind_control_stream(ctx->h3conn, ctrl_stream_id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }

  sinfo.stream_id = -1;
  sinfo.stream_flags = MSG_STREAM_UNI;
  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo,
                  &len);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }
  qpack_enc_stream_id = sinfo.stream_id;

  sinfo.stream_id = -1;
  sinfo.stream_flags = MSG_STREAM_UNI;
  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo,
                  &len);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto fail;
  }
  qpack_dec_stream_id = sinfo.stream_id;

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

static void cf_linuxq_adjust_pollset(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  bool want_recv, want_send;

  if(!ctx->qconn)
    return;

  Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);

  if(want_recv || want_send) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    struct cf_call_data save;
    bool s_exhaust;

    CF_DATA_SAVE(save, cf, data);
    s_exhaust = stream && stream->id >= 0;
    want_recv = (want_recv || s_exhaust);
    want_send = (!s_exhaust && want_send);

    Curl_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
}

static void cf_linuxq_ctx_clear(struct cf_linuxq_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
  if(ctx->h3conn)
    nghttp3_conn_del(ctx->h3conn);
  if(ctx->qconn)
    free(ctx->qconn);
  Curl_dyn_free(&ctx->scratch);
  Curl_hash_clean(&ctx->streams);
  Curl_hash_destroy(&ctx->streams);
  Curl_ssl_peer_cleanup(&ctx->peer);

  memset(ctx, 0, sizeof(*ctx));
  ctx->call_data = save;
}

static CURLcode cf_linuxq_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data, bool *done)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  struct quic_connection_close cclose;
  CURLcode result = CURLE_OK;
  int rc;

  if(cf->shutdown || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;

  if(!ctx->shutdown_started) {

    ctx->shutdown_started = TRUE;
    memset(&cclose, 0, sizeof(cclose));
    rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE,
                    &cclose, sizeof(cclose));
    if(rc) {
      result = CURLE_WRITE_ERROR;
      goto out;
    }
    CURL_TRC_CF(data, cf, "start shutdown(err_type=%hu, err_code=%u) -> %d",
                cclose.frame, cclose.errcode, rc);
  }
  *done = TRUE;

out:
  CF_DATA_RESTORE(cf, save);
  return result;
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

static CURLcode cf_linuxq_data_event(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     int event, int arg1, void *arg2)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
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
      (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
    }
    break;
  }
  case CF_CTRL_DATA_IDLE: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    CURL_TRC_CF(data, cf, "data idle");
    if(stream && !stream->closed) {
      /* XXX: what to do? */
/*
      result = check_and_set_expiry(cf, data, NULL);
      if(result)
        CURL_TRC_CF(data, cf, "data idle, check_and_set_expiry -> %d", result);
*/
    }
    break;
  }
  default:
    break;
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_linuxq_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  bool done;
  cf_linuxq_shutdown(cf, data, &done);
}

static void cf_linuxq_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  if(ctx && ctx->qconn) {
    cf_linuxq_conn_close(cf, data);
    cf_linuxq_ctx_clear(ctx);
    CURL_TRC_CF(data, cf, "close");
  }
  cf->connected = FALSE;
  CF_DATA_RESTORE(cf, save);
}

static void cf_linuxq_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  CURL_TRC_CF(data, cf, "destroy");
  if(ctx) {
    cf_linuxq_ctx_clear(ctx);
    free(ctx);
  }
  cf->ctx = NULL;
  /* No CF_DATA_RESTORE(cf, save) possible */
  (void)save;
}

#ifdef USE_OPENSSL
/* The "new session" callback must return zero if the session can be removed
 * or non-zero if the session has been put into the session cache.
 */
static int quic_ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid)
{
  struct Curl_cfilter *cf;
  struct cf_linuxq_ctx *ctx;
  struct Curl_easy *data;

  cf = (struct Curl_cfilter *)SSL_get_app_data(ssl);
  ctx = cf? cf->ctx : NULL;
  data = cf? CF_DATA_CURRENT(cf) : NULL;
  if(cf && data && ctx) {
    Curl_ossl_add_session(cf, data, &ctx->peer, ssl_sessionid);
    return 1;
  }
  return 0;
}
#endif /* USE_OPENSSL */

static CURLcode tls_ctx_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              void *user_data)
{
  struct curl_tls_ctx *ctx = user_data;
  (void)cf;
#ifdef USE_OPENSSL
  crypto_ssl_configure_context(ctx->ossl.ssl_ctx);
  /* Enable the session cache because it is a prerequisite for the
   * "new session" callback. Use the "external storage" mode to prevent
   * OpenSSL from creating an internal session cache.
   */
  SSL_CTX_set_session_cache_mode(ctx->ossl.ssl_ctx,
                                 SSL_SESS_CACHE_CLIENT |
                                 SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(ctx->ossl.ssl_ctx, quic_ossl_new_session_cb);
#elif defined(USE_GNUTLS)
  if(crypto_gtls_configure_session(ctx->gtls.session)) {
    failf(data, "crypto_gtls_configure_session failed");
    return CURLE_FAILED_INIT;
  }
#elif defined(USE_WOLFSSL)
  crypto_wssl_configure_context(ctx->wssl.ctx);
#endif
  return CURLE_OK;
}

static struct linuxq_conn *cf_conn_create(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct linuxq_conn *ret;
  ret = calloc(1, sizeof(*ret));

  return ret;
}

/*
 * Might be called twice for happy eyeballs.
 */
static CURLcode cf_connect_start(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  socklen_t len = sizeof(struct quic_transport_param);
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int rc;

  Curl_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  Curl_hash_offt_init(&ctx->streams, 63, h3_stream_hash_free);

  result = Curl_ssl_peer_init(&ctx->peer, cf, TRNSPRT_QUIC);
  if(result)
    return result;

#define H3_ALPN "\x2h3\x5h3-29"
  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               H3_ALPN, sizeof(H3_ALPN) - 1,
                               tls_ctx_setup, &ctx->tls, cf);
  if(result)
    return result;

#ifdef USE_OPENSSL
  SSL_set_quic_use_legacy_codepoint(ctx->tls.ossl.ssl, 0);
#endif

  result = vquic_ctx_init(&ctx->q);
  if(result)
    return result;

  Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL);
  if(!sockaddr)
    return CURLE_QUIC_CONNECT_ERROR;

  ctx->qconn = calloc(1, sizeof(*ctx->qconn));
  if(!ctx->qconn)
    return CURLE_OUT_OF_MEMORY;

  rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, "h3, h3-29",
                  sizeof("h3, h3-29"));
  if(rc)
    return CURLE_QUIC_CONNECT_ERROR;

  ctx->transport_params.max_idle_timeout = CURL_QUIC_MAX_IDLE_MS * 1000;
  ctx->transport_params.plpmtud_probe_timeout = 5000000;
  ctx->transport_params.grease_quic_bit = 1;
  rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
                  &ctx->transport_params, len);
  if(rc)
    return CURLE_FAILED_INIT;

  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
                  &ctx->transport_params, &len);
  if(rc)
    return CURLE_FAILED_INIT;

  if(!ctx->qconn)
    ctx->qconn = cf_conn_create(cf, data);
  if(!ctx->qconn)
    return errno;

  return CURLE_OK;
}

static CURLcode qng_verify_peer(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  cf->conn->httpversion = 30;
  cf->conn->bundle->multiuse = BUNDLE_MULTIPLEX;

  return Curl_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}

static CURLcode cf_linuxq_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool blocking, bool *done)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  struct curltime now;
  struct quic_event_option eopt;
  struct quic_transport_param rp = {0};
  socklen_t len;
  int rc;
  uint8_t i;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the QUIC filter first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, blocking, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  now = Curl_now();

  CF_DATA_SAVE(save, cf, data);

  if(ctx->reconnect_at.tv_sec && Curl_timediff(now, ctx->reconnect_at) < 0) {
    /* Not time yet to attempt the next connect */
    CURL_TRC_CF(data, cf, "waiting for reconnect time");
    goto out;
  }

  if(!ctx->qconn) {
    ctx->started_at = now;
    result = cf_connect_start(cf, data);
    if(result)
      goto out;
  }

  rc = crypto_handshake(cf, data);
  if(rc)
    return rc;

  /*
   * XXX: We only use QUIC_EVENT_CONNECTION_CLOSE,
   * and QUIC_EVENT_STREAM_UPDATE for now
   */
  for(i = 1; i < QUIC_EVENT_END; i++) {
    eopt.type = i;
    eopt.on = 1;
    rc = setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &eopt,
                    sizeof(eopt));
    if(rc)
      return CURLE_QUIC_CONNECT_ERROR;
  }

  now = Curl_now();
  ctx->handshake_at = now; /* XXX: move into tls code callback? */
  CURL_TRC_CF(data, cf, "handshake complete after %dms",
             (int)Curl_timediff(now, ctx->started_at));

  len = sizeof(rp);
  rp.remote = 1;
  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &rp,
                  &len);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  ctx->max_bidi_streams = rp.max_streams_bidi;

  result = qng_verify_peer(cf, data);
  if(result)
    goto out;

  if(init_ngh3_conn(cf) != CURLE_OK) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  CURL_TRC_CF(data, cf, "peer verified");
  cf->connected = TRUE;
  cf->conn->alpn = CURL_HTTP_VERSION_3;
  *done = TRUE;
  connkeep(cf->conn, "HTTP/3 default");

out:
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result) {
    struct ip_quadruple ip;

    Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
    infof(data, "QUIC connect to %s port %u failed: %s",
          ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
  }
#endif
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

/* incoming data frames on the h3 stream */
static ssize_t cf_linuxq_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t blen, CURLcode *err)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nread = -1;
  struct cf_call_data save;
  (void)ctx;
  (void)buf;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  *err = CURLE_OK;

  if(!stream || ctx->shutdown_started) {
    *err = CURLE_RECV_ERROR;
    goto out;
  }

  if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] xfer write failed", stream->id);
    cf_linuxq_stream_close(cf, data, stream);
    *err = stream->xfer_result;
    nread = -1;
    goto out;
  }
  else if(stream->closed) {
    nread = 0;
    goto out;
  }

  *err = cf_progress_ingress(cf, data);
  if(!*err)
    *err = CURLE_AGAIN;

  nread = -1;

out:
  CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] cf_recv(blen=%zu) -> %zd, %d",
              stream? stream->id : -1, blen, nread, *err);
  CF_DATA_RESTORE(cf, save);
  return nread;
}

static nghttp3_ssize
cb_h3_read_req_body(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags, void *user_data,
                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t nvecs = 0;
  (void)cf;
  (void)conn;
  (void)stream_id;
  (void)vec;
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


  /* When we stopped sending and everything in `sendbuf` is "in flight",
   * we are at the end of the request body. */
  if(stream->upload_left == 0) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }

  CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] read req body -> "
              "%d vecs%s (left=%" CURL_FORMAT_CURL_OFF_T ")",
              stream->id, (int)nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF?" EOF":"",
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
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
  int64_t sid;
  struct quic_stream_info sinfo;
  socklen_t slen;
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

  sinfo.stream_id = -1;
  sinfo.stream_flags = 0;
  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo,
                  &slen);
  if(rc) {
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }
  sid = sinfo.stream_id;
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
      CURL_TRC_CF(data, cf, "h3sid[%" CURL_PRId64 "] failed to send, "
                  "connection is closing", stream->id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" CURL_PRId64 "] failed to send -> "
                  "%d (%s)", stream->id, rc, nghttp3_strerror(rc));
      break;
    }
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" CURL_PRId64 "] OPENED stream for %s",
          stream->id, data->state.url);
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" CURL_PRId64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].namelen, nva[i].name,
            (int)nva[i].valuelen, nva[i].value);
    }
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  return nwritten;
}

static ssize_t cf_linuxq_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const void *buf, size_t len, bool eos,
                              CURLcode *err)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t sent = 0;
  struct cf_call_data save;
  CURLcode result;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  *err = CURLE_OK;

  (void)eos; /* TODO: use for stream EOF and block handling */
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
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] xfer write failed", stream->id);
    cf_linuxq_stream_close(cf, data, stream);
    *err = stream->xfer_result;
    sent = -1;
    goto out;
  }
  else if(stream->upload_blocked_len) {
    /* the data in `buf` has already been submitted or added to the
     * buffers, but have been EAGAINed on the last invocation. */
    DEBUGASSERT(len >= stream->upload_blocked_len);
    if(len < stream->upload_blocked_len) {
      /* Did we get called again with a smaller `len`? This should not
       * happen. We are not prepared to handle that. */
      failf(data, "HTTP/3 send again with decreased length");
      *err = CURLE_HTTP3;
      sent = -1;
      goto out;
    }
    sent = (ssize_t)stream->upload_blocked_len;
    stream->upload_blocked_len = 0;
  }
  else if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] discarding data"
                  "on closed stream with response", stream->id);
      *err = CURLE_OK;
      sent = (ssize_t)len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] send_body(len=%zu) "
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
  (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);

  result = cf_progress_egress(cf, data);
  if(result) {
    *err = result;
    sent = -1;
  }

  if(stream && sent > 0) {
    /* We have unacknowledged DATA and cannot report success to our
     * caller. Instead we EAGAIN and remember how much we have already
     * "written" into our various internal connection buffers. */
    stream->upload_blocked_len = sent;
    CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] cf_send(len=%zu), "
                "-> EGAIN", stream->id, len);
    *err = CURLE_AGAIN;
    sent = -1;
  }

out:
  CURL_TRC_CF(data, cf, "[%" CURL_PRId64 "] cf_send(len=%zu) -> %zd, %d",
              stream? stream->id : -1, len, sent, *err);
  CF_DATA_RESTORE(cf, save);
  return sent;
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
static bool cf_linuxq_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  (void)cf;
  (void)data;
  return FALSE;
}

static struct cmsghdr *get_cmsg_stream_info(struct msghdr *msg)
{
  struct cmsghdr *cm = NULL;

  for(cm = CMSG_FIRSTHDR(msg); cm != NULL; cm = CMSG_NXTHDR(msg, cm))
    if(cm->cmsg_len == CMSG_LEN(sizeof(struct quic_stream_info)) &&
       cm->cmsg_level == IPPROTO_QUIC && cm->cmsg_type == QUIC_STREAM_INFO)
      break;

  return cm;
}

static CURLcode cf_linuxq_recv_pkt(struct Curl_cfilter *cf,
                         struct Curl_easy *data, struct msghdr *msg,
                         size_t pktlen)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct cmsghdr *cm = NULL;
  const unsigned char *pkt = msg->msg_iov->iov_base;
  union quic_event *qev;
  struct quic_stream_info sinfo;
  int rv;

  cm = get_cmsg_stream_info(msg);

  if(msg->msg_flags & MSG_NOTIFICATION) {
    if(pktlen < 1)
      return CURLE_RECV_ERROR;

    switch(pkt[0]) {
    case QUIC_EVENT_CONNECTION_CLOSE:
      if(pktlen < 1 + sizeof(struct quic_connection_close))
        return CURLE_HTTP3;
      qev = (union quic_event *)&pkt[1];
      ctx->last_error = qev->close.errcode;
      return CURLE_RECV_ERROR;
    case QUIC_EVENT_STREAM_UPDATE:
      if(pktlen < 1 + sizeof(struct quic_stream_update))
        return CURLE_HTTP3;
      qev = (union quic_event *)&pkt[1];
      if(qev->update.errcode) /* XXX: is this correct? */
        ctx->last_error = qev->update.errcode;
      infof(data, "stream update id=%lu state=%u errcode=%u", qev->update.id,
            qev->update.state, qev->update.errcode);
      return CURLE_OK;
    case QUIC_EVENT_STREAM_MAX_STREAM:
      if(pktlen < 1 + sizeof(uint64_t))
        return CURLE_HTTP3;
      qev = (union quic_event *)&pkt[1];

      if(!cm)
        return CURLE_HTTP3;
      memcpy(&sinfo, CMSG_DATA(cm), sizeof(sinfo));

      if(!(sinfo.stream_id & QUIC_STREAM_TYPE_UNI_MASK)) {
        ctx->max_bidi_streams = qev->max_stream;
        CURL_TRC_CF(data, cf, "max bidi streams now %" CURL_PRIu64 ", used %"
                    CURL_PRIu64, (curl_uint64_t)ctx->max_bidi_streams,
                    (curl_uint64_t)ctx->used_bidi_streams);
      }
      return CURLE_OK;
    case QUIC_EVENT_CONNECTION_MIGRATION:
      if(pktlen < 1 + sizeof(uint8_t))
        return CURLE_HTTP3;
      qev = (union quic_event *)&pkt[1];
      infof(data, "connection migration local_migration=%hhu",
            qev->local_migration);
      return CURLE_OK;
    case QUIC_EVENT_KEY_UPDATE:
      if(pktlen < 1 + sizeof(uint8_t))
        return CURLE_HTTP3;
      qev = (union quic_event *)&pkt[1];
      infof(data, "key update key_update_phase=%hhu",
            qev->key_update_phase);
      return CURLE_OK;
    case QUIC_EVENT_NEW_TOKEN:
      /* XXX: convert/store token? */
      infof(data, "new token");
      return CURLE_OK;
    default:
      return CURLE_HTTP3;
    }
  }

  if(!cm)
    return CURLE_RECV_ERROR;

  memcpy(&sinfo, CMSG_DATA(cm), sizeof(sinfo));

  rv = cf_linuxq_recv_stream_data(cf, data, pkt, pktlen, sinfo.stream_id,
                                  sinfo.stream_flags);
  if(rv) {
    CURL_TRC_CF(data, cf, "ingress, read_pkt -> %s (%d)",
                nghttp3_strerror(rv), rv);

    return CURLE_RECV_ERROR;
  }

  return CURLE_OK;
}

static CURLcode cf_linuxq_recvmsg_packets(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct cf_quic_ctx *qctx = &ctx->q;
  struct iovec msg_iov;
  struct msghdr msg;
  uint8_t buf[64*1024];
  ssize_t nread;
  char errstr[STRERROR_LEN];
  CURLcode result = CURLE_OK;
  uint8_t msg_ctrl[CMSG_SPACE(sizeof(struct quic_stream_info))];

  msg_iov.iov_base = buf;
  msg_iov.iov_len = (int)sizeof(buf);

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;
  msg.msg_control = msg_ctrl;
  msg.msg_controllen = sizeof(msg_ctrl);

  nread = recvmsg(qctx->sockfd, &msg, 0);
  if(nread == -1) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK)
      goto out;
    if(!cf->connected && SOCKERRNO == ECONNREFUSED) {
      struct ip_quadruple ip;
      Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
      failf(data, "QUIC: connection to %s port %u refused",
            ip.remote_ip, ip.remote_port);
      result = CURLE_COULDNT_CONNECT;
      goto out;
    }
    Curl_strerror(SOCKERRNO, errstr, sizeof(errstr));
    failf(data, "QUIC: recvmsg() unexpectedly returned %zd (errno=%d; %s)",
                nread, SOCKERRNO, errstr);
    result = CURLE_RECV_ERROR;
    goto out;
  }

  result = cf_linuxq_recv_pkt(cf, data, &msg, nread);

  CURL_TRC_CF(data, cf, "recvd 1 packet with %zd bytes -> %d", nread, result);
out:
  return result;
}

static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  result = cf_linuxq_recvmsg_packets(cf, data);
  if(!result) {
    if(!ctx->q.got_first_byte) {
      ctx->q.got_first_byte = TRUE;
      ctx->q.first_byte_at = ctx->q.last_op;
    }
    ctx->q.last_io = ctx->q.last_op;
  }
  return result;
}

static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  struct quic_stream_info *sinfo;
  struct cmsghdr *cm;
  struct quic_errinfo einfo;
  int64_t stream_id;
  nghttp3_ssize veccnt;
  ssize_t sent;
  uint32_t flags;
  int fin, rc;
  struct msghdr msg = {0};
  nghttp3_vec vec[16];
  uint8_t msg_ctrl[CMSG_SPACE(sizeof(struct quic_stream_info))];

  msg.msg_iov = (struct iovec *)&vec;
  msg.msg_control = msg_ctrl;
  msg.msg_controllen = sizeof(msg_ctrl);

  cm = CMSG_FIRSTHDR(&msg);
  cm->cmsg_level = IPPROTO_QUIC;
  cm->cmsg_type = 0;
  cm->cmsg_len = CMSG_LEN(sizeof(*sinfo));

  sinfo = (struct quic_stream_info *)CMSG_DATA(cm);

  for(;;) {
    veccnt = 0;
    stream_id = -1;
    fin = 0;
    flags = 0;

    if(ctx->h3conn) {
      veccnt = nghttp3_conn_writev_stream(ctx->h3conn, &stream_id,
                                          &fin, vec, sizeof(vec) /
                                          sizeof(vec[0]));
      if(veccnt < 0) {
        failf(data, "nghttp3_conn_writev_stream returned error: %s",
              nghttp3_strerror((int)veccnt));

        einfo.stream_id = (uint64_t)stream_id;
        einfo.errcode = (uint32_t)
                        nghttp3_err_infer_quic_app_error_code((int)veccnt);
        setsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &einfo,
                   sizeof(einfo));
        return CURLE_SEND_ERROR;
      }

      if(fin)
        flags |= MSG_STREAM_FIN;
      else if(veccnt == 0)
        goto out;
    }

    sinfo->stream_id = (uint64_t)stream_id;
    sinfo->stream_flags = flags;
    msg.msg_iovlen = veccnt;

    sent = sendmsg(ctx->q.sockfd, &msg, 0);
    if(sent == 0)
      goto out;

    if(sent == -1) {
      switch(SOCKERRNO) {
      case EAGAIN:
#if EAGAIN != EWOULDBLOCK
      case EWOULDBLOCK:
#endif
        return CURLE_AGAIN;
      default:
        failf(data, "sendmsg() returned %zd (errno %d)", sent, errno);
        return CURLE_SEND_ERROR;
      }
    }

    stream->upload_left -= sent;

    rc = nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, sent);
    if(rc) {
      failf(data, "nghttp3_conn_add_write_offset returned error: %s\n",
            nghttp3_strerror(rc));
      return CURLE_SEND_ERROR;
    }
  }

out:
  return CURLE_OK;
}

static CURLcode cf_linuxq_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int query, int *pres1, void *pres2)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
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
      *pres1 = (max_streams > INT_MAX)? INT_MAX : (int)max_streams;
    }
    else  /* transport params not arrived yet? take our default. */
      *pres1 = (int)Curl_multi_max_concurrent_streams(data->multi);
    CURL_TRC_CF(data, cf, "query conn[%" CURL_FORMAT_CURL_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%zu in use)",
                cf->conn->connection_id, *pres1, CONN_INUSE(cf->conn));
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->q.got_first_byte) {
      timediff_t ms = Curl_timediff(ctx->q.first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX)? (int)ms : INT_MAX;
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
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_linuxq_conn_is_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *input_pending)
{
  struct cf_linuxq_ctx *ctx = cf->ctx;
  bool alive = FALSE;
  struct cf_call_data save;
  timediff_t idletime;
  uint64_t idle_ms;
  struct quic_transport_param rp = {0};
  socklen_t len = sizeof(struct quic_transport_param);
  int rc;

  CF_DATA_SAVE(save, cf, data);
  *input_pending = FALSE;
  if(!ctx->qconn || ctx->shutdown_started)
    goto out;

  /* Both sides of the QUIC connection announce they max idle times in
   * the transport parameters. Look at the minimum of both and if
   * we exceed this, regard the connection as dead. The other side
   * may have completely purged it and will no longer respond
   * to any packets from us. */
  rp.remote = 1;
  rc = getsockopt(ctx->q.sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &rp,
                  &len);
  if(rc)
    goto out;

  idle_ms = ctx->transport_params.max_idle_timeout;
  if(rp.max_idle_timeout && rp.max_idle_timeout < idle_ms)
    idle_ms = rp.max_idle_timeout;
  idle_ms /= 1000;

  idletime = Curl_timediff(Curl_now(), ctx->q.last_io);
  if(idletime > 0 && (uint64_t)idletime > idle_ms)
    goto out;

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    goto out;

  alive = TRUE;
  if(*input_pending) {
    CURLcode result;
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    result = cf_progress_ingress(cf, data);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result? FALSE : TRUE;
  }

out:
  CF_DATA_RESTORE(cf, save);
  return alive;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX,
  0,
  cf_linuxq_destroy,
  cf_linuxq_connect,
  cf_linuxq_close,
  cf_linuxq_shutdown,
  Curl_cf_def_get_host,
  cf_linuxq_adjust_pollset,
  cf_linuxq_data_pending,
  cf_linuxq_send,
  cf_linuxq_recv,
  cf_linuxq_data_event,
  cf_linuxq_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_linuxq_query,
};

CURLcode Curl_cf_linuxq_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct Curl_addrinfo *ai)
{
  struct cf_linuxq_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL, *quic_cf = NULL;
  CURLcode result;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_linuxq_ctx_clear(ctx);

  result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);
  if(result)
    goto out;

  result = Curl_cf_quic_sock_create(&quic_cf, data, conn, ai, TRNSPRT_QUIC);
  if(result)
    goto out;

  cf->conn = conn;
  quic_cf->conn = cf->conn;
  quic_cf->sockindex = cf->sockindex;
  cf->next = quic_cf;

out:
  *pcf = (!result)? cf : NULL;
  if(result) {
    if(quic_cf)
      Curl_conn_cf_discard_sub(cf, quic_cf, data, TRUE);
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }
  return result;
}

bool Curl_conn_is_linuxq(const struct Curl_easy *data,
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

#endif
