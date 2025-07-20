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

#include "../curl_setup.h"

#if defined(USE_HTTP3) && \
  (defined(USE_OPENSSL) || defined(USE_GNUTLS) || defined(USE_WOLFSSL))

#ifdef USE_OPENSSL
#include <openssl/err.h>
#include "../vtls/openssl.h"
#elif defined(USE_GNUTLS)
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <nettle/sha2.h>
#include "../vtls/gtls.h"
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include "../vtls/wolfssl.h"
#endif

#include "../urldata.h"
#include "../curl_trc.h"
#include "../cfilters.h"
#include "../multiif.h"
#include "../vtls/keylog.h"
#include "../vtls/vtls.h"
#include "../vtls/vtls_scache.h"
#include "vquic-tls.h"

/* The last 3 #include files should be in this order */
#include "../curl_printf.h"
#include "../curl_memory.h"
#include "../memdebug.h"

CURLcode Curl_vquic_tls_init(struct curl_tls_ctx *ctx,
                             struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct ssl_peer *peer,
                             const struct alpn_spec *alpns,
                             Curl_vquic_tls_ctx_setup *cb_setup,
                             void *cb_user_data, void *ssl_user_data,
                             Curl_vquic_session_reuse_cb *session_reuse_cb)
{
  char tls_id[80];
  CURLcode result;

#ifdef USE_OPENSSL
  Curl_ossl_version(tls_id, sizeof(tls_id));
#elif defined(USE_GNUTLS)
  Curl_gtls_version(tls_id, sizeof(tls_id));
#elif defined(USE_WOLFSSL)
  Curl_wssl_version(tls_id, sizeof(tls_id));
#else
#error "no TLS lib in used, should not happen"
  return CURLE_FAILED_INIT;
#endif
  (void)session_reuse_cb;
  result = Curl_ssl_peer_init(peer, cf, tls_id, TRNSPRT_QUIC);
  if(result)
    return result;

#ifdef USE_OPENSSL
  (void)result;
  return Curl_ossl_ctx_init(&ctx->ossl, cf, data, peer, alpns,
                            cb_setup, cb_user_data, NULL, ssl_user_data,
                            session_reuse_cb);
#elif defined(USE_GNUTLS)
  return Curl_gtls_ctx_init(&ctx->gtls, cf, data, peer, alpns,
                            cb_setup, cb_user_data, ssl_user_data,
                            session_reuse_cb);
#elif defined(USE_WOLFSSL)
  return Curl_wssl_ctx_init(&ctx->wssl, cf, data, peer, alpns,
                            cb_setup, cb_user_data,
                            ssl_user_data, session_reuse_cb);
#else
#error "no TLS lib in used, should not happen"
  return CURLE_FAILED_INIT;
#endif
}

void Curl_vquic_tls_cleanup(struct curl_tls_ctx *ctx)
{
#ifdef USE_OPENSSL
  if(ctx->ossl.ssl)
    SSL_free(ctx->ossl.ssl);
  if(ctx->ossl.ssl_ctx)
    SSL_CTX_free(ctx->ossl.ssl_ctx);
#elif defined(USE_GNUTLS)
  if(ctx->gtls.session)
    gnutls_deinit(ctx->gtls.session);
  Curl_gtls_shared_creds_free(&ctx->gtls.shared_creds);
#elif defined(USE_WOLFSSL)
  if(ctx->wssl.ssl)
    wolfSSL_free(ctx->wssl.ssl);
  if(ctx->wssl.ssl_ctx)
    wolfSSL_CTX_free(ctx->wssl.ssl_ctx);
#endif
  memset(ctx, 0, sizeof(*ctx));
}

CURLcode Curl_vquic_tls_before_recv(struct curl_tls_ctx *ctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
#ifdef USE_OPENSSL
  if(!ctx->ossl.x509_store_setup) {
    CURLcode result = Curl_ssl_setup_x509_store(cf, data, ctx->ossl.ssl_ctx);
    if(result)
      return result;
    ctx->ossl.x509_store_setup = TRUE;
  }
#elif defined(USE_WOLFSSL)
  if(!ctx->wssl.x509_store_setup) {
    CURLcode result = Curl_wssl_setup_x509_store(cf, data, &ctx->wssl);
    if(result)
      return result;
  }
#elif defined(USE_GNUTLS)
  if(!ctx->gtls.shared_creds->trust_setup) {
    CURLcode result = Curl_gtls_client_trust_setup(cf, data, &ctx->gtls);
    if(result)
      return result;
  }
#else
  (void)ctx; (void)cf; (void)data;
#endif
  return CURLE_OK;
}

CURLcode Curl_vquic_tls_verify_peer(struct curl_tls_ctx *ctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ssl_peer *peer)
{
  struct ssl_primary_config *conn_config;
  CURLcode result = CURLE_OK;

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!conn_config)
    return CURLE_FAILED_INIT;

#ifdef USE_OPENSSL
  (void)conn_config;
  result = Curl_ossl_check_peer_cert(cf, data, &ctx->ossl, peer);
#elif defined(USE_GNUTLS)
  if(conn_config->verifyhost) {
    result = Curl_gtls_verifyserver(data, ctx->gtls.session,
                                    conn_config, &data->set.ssl, peer,
                                    data->set.str[STRING_SSL_PINNEDPUBLICKEY]);
    if(result)
      return result;
  }
#elif defined(USE_WOLFSSL)
  (void)data;
  if(conn_config->verifyhost) {
    char *snihost = peer->sni ? peer->sni : peer->hostname;
    WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(ctx->wssl.ssl);
    if(wolfSSL_X509_check_host(cert, snihost, strlen(snihost), 0, NULL)
          == WOLFSSL_FAILURE) {
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    wolfSSL_X509_free(cert);
  }
  if(!result)
    result = Curl_wssl_verify_pinned(cf, data, &ctx->wssl);
#endif
  /* on error, remove any session we might have in the pool */
  if(result)
    Curl_ssl_scache_remove_all(cf, data, peer->scache_key);
  return result;
}


bool Curl_vquic_tls_get_ssl_info(struct curl_tls_ctx *ctx,
                                 bool give_ssl_ctx,
                                 struct curl_tlssessioninfo *info)
{
#ifdef USE_OPENSSL
  info->backend = CURLSSLBACKEND_OPENSSL;
  info->internals = give_ssl_ctx ?
                    (void *)ctx->ossl.ssl_ctx : (void *)ctx->ossl.ssl;
  return TRUE;
#elif defined(USE_GNUTLS)
  (void)give_ssl_ctx; /* gnutls always returns its session */
  info->backend = CURLSSLBACKEND_GNUTLS;
  info->internals = ctx->gtls.session;
  return TRUE;
#elif defined(USE_WOLFSSL)
  info->backend = CURLSSLBACKEND_WOLFSSL;
  info->internals = give_ssl_ctx ?
                    (void *)ctx->wssl.ssl_ctx : (void *)ctx->wssl.ssl;
  return TRUE;
#else
  return FALSE;
#endif
}

void Curl_vquic_report_handshake(struct curl_tls_ctx *ctx,
                                 struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  (void)cf;
#ifdef USE_OPENSSL
  (void)cf;
  Curl_ossl_report_handshake(data, &ctx->ossl);
#elif defined(USE_GNUTLS)
  Curl_gtls_report_handshake(data, &ctx->gtls);
#elif defined(USE_WOLFSSL)
  Curl_wssl_report_handshake(data, &ctx->wssl);
#else
  (void)data;
  (void)ctx;
#endif
}

#endif /* !USE_HTTP3 && (USE_OPENSSL || USE_GNUTLS || USE_WOLFSSL) */
