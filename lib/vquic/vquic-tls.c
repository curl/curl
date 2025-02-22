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

#if defined(USE_HTTP3) && \
  (defined(USE_OPENSSL) || defined(USE_GNUTLS) || defined(USE_WOLFSSL))

#ifdef USE_OPENSSL
#include <openssl/err.h>
#include "vtls/openssl.h"
#elif defined(USE_GNUTLS)
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <nettle/sha2.h>
#include "vtls/gtls.h"
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include "vtls/wolfssl.h"
#endif

#include "urldata.h"
#include "curl_trc.h"
#include "cfilters.h"
#include "multiif.h"
#include "vtls/keylog.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "vquic-tls.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if defined(USE_WOLFSSL)

#define QUIC_CIPHERS                                                          \
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"               \
  "POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define QUIC_GROUPS "P-256:P-384:P-521"

#if defined(HAVE_SECRET_CALLBACK)
static void keylog_callback(const WOLFSSL *ssl, const char *line)
{
  (void)ssl;
  Curl_tls_keylog_write_line(line);
}
#endif

static CURLcode wssl_init_ctx(struct curl_tls_ctx *ctx,
                              struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              Curl_vquic_tls_ctx_setup *cb_setup,
                              void *cb_user_data)
{
  struct ssl_primary_config *conn_config;
  CURLcode result = CURLE_FAILED_INIT;

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!conn_config) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  ctx->wssl.ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  if(!ctx->wssl.ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(cb_setup) {
    result = cb_setup(cf, data, cb_user_data);
    if(result)
      goto out;
  }

  wolfSSL_CTX_set_default_verify_paths(ctx->wssl.ctx);

  if(wolfSSL_CTX_set_cipher_list(ctx->wssl.ctx, conn_config->cipher_list13 ?
                                 conn_config->cipher_list13 :
                                 QUIC_CIPHERS) != 1) {
    char error_buffer[256];
    ERR_error_string_n(ERR_get_error(), error_buffer, sizeof(error_buffer));
    failf(data, "wolfSSL failed to set ciphers: %s", error_buffer);
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  if(wolfSSL_CTX_set1_groups_list(ctx->wssl.ctx, conn_config->curves ?
                                  conn_config->curves :
                                  (char *)QUIC_GROUPS) != 1) {
    failf(data, "wolfSSL failed to set curves");
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  /* Open the file if a TLS or QUIC backend has not done this before. */
  Curl_tls_keylog_open();
  if(Curl_tls_keylog_enabled()) {
#if defined(HAVE_SECRET_CALLBACK)
    wolfSSL_CTX_set_keylog_callback(ctx->wssl.ctx, keylog_callback);
#else
    failf(data, "wolfSSL was built without keylog callback");
    result = CURLE_NOT_BUILT_IN;
    goto out;
#endif
  }

  if(conn_config->verifypeer) {
    const char * const ssl_cafile = conn_config->CAfile;
    const char * const ssl_capath = conn_config->CApath;

    wolfSSL_CTX_set_verify(ctx->wssl.ctx, SSL_VERIFY_PEER, NULL);
    if(ssl_cafile || ssl_capath) {
      /* tell wolfSSL where to find CA certificates that are used to verify
         the server's certificate. */
      int rc =
        wolfSSL_CTX_load_verify_locations_ex(ctx->wssl.ctx, ssl_cafile,
                                             ssl_capath,
                                             WOLFSSL_LOAD_FLAG_IGNORE_ERR);
      if(SSL_SUCCESS != rc) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data, "error setting certificate verify locations:"
              "  CAfile: %s CApath: %s",
              ssl_cafile ? ssl_cafile : "none",
              ssl_capath ? ssl_capath : "none");
        result = CURLE_SSL_CACERT_BADFILE;
        goto out;
      }
      infof(data, " CAfile: %s", ssl_cafile ? ssl_cafile : "none");
      infof(data, " CApath: %s", ssl_capath ? ssl_capath : "none");
    }
#ifdef CURL_CA_FALLBACK
    else {
      /* verifying the peer without any CA certificates will not work so
         use wolfSSL's built-in default as fallback */
      wolfSSL_CTX_set_default_verify_paths(ctx->wssl.ctx);
    }
#endif
  }
  else {
    wolfSSL_CTX_set_verify(ctx->wssl.ctx, SSL_VERIFY_NONE, NULL);
  }

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    Curl_set_in_callback(data, TRUE);
    result = (*data->set.ssl.fsslctx)(data, ctx->wssl.ctx,
                                      data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, FALSE);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      goto out;
    }
  }
  result = CURLE_OK;

out:
  if(result && ctx->wssl.ctx) {
    SSL_CTX_free(ctx->wssl.ctx);
    ctx->wssl.ctx = NULL;
  }
  return result;
}

/** SSL callbacks ***/

static CURLcode wssl_init_ssl(struct curl_tls_ctx *ctx,
                              struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct ssl_peer *peer,
                              const char *alpn, size_t alpn_len,
                              void *user_data)
{
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

  DEBUGASSERT(!ctx->wssl.handle);
  DEBUGASSERT(ctx->wssl.ctx);
  ctx->wssl.handle = wolfSSL_new(ctx->wssl.ctx);

  wolfSSL_set_app_data(ctx->wssl.handle, user_data);
  wolfSSL_set_connect_state(ctx->wssl.handle);
  wolfSSL_set_quic_use_legacy_codepoint(ctx->wssl.handle, 0);

  if(alpn)
    wolfSSL_set_alpn_protos(ctx->wssl.handle, (const unsigned char *)alpn,
                            (unsigned int)alpn_len);

  if(peer->sni) {
    wolfSSL_UseSNI(ctx->wssl.handle, WOLFSSL_SNI_HOST_NAME,
                   peer->sni, (unsigned short)strlen(peer->sni));
  }

  if(ssl_config->primary.cache_session) {
    (void)Curl_wssl_setup_session(cf, data, &ctx->wssl, peer->scache_key);
  }

  return CURLE_OK;
}
#endif /* defined(USE_WOLFSSL) */

CURLcode Curl_vquic_tls_init(struct curl_tls_ctx *ctx,
                             struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct ssl_peer *peer,
                             const char *alpn, size_t alpn_len,
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
  return Curl_ossl_ctx_init(&ctx->ossl, cf, data, peer,
                            (const unsigned char *)alpn, alpn_len,
                            cb_setup, cb_user_data, NULL, ssl_user_data);
#elif defined(USE_GNUTLS)
  return Curl_gtls_ctx_init(&ctx->gtls, cf, data, peer,
                            (const unsigned char *)alpn, alpn_len,
                            cb_setup, cb_user_data, ssl_user_data,
                            session_reuse_cb);
#elif defined(USE_WOLFSSL)
  result = wssl_init_ctx(ctx, cf, data, cb_setup, cb_user_data);
  if(result)
    return result;

  (void)session_reuse_cb;
  return wssl_init_ssl(ctx, cf, data, peer, alpn, alpn_len, ssl_user_data);
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
  if(ctx->wssl.handle)
    wolfSSL_free(ctx->wssl.handle);
  if(ctx->wssl.ctx)
    wolfSSL_CTX_free(ctx->wssl.ctx);
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
  result = Curl_oss_check_peer_cert(cf, data, &ctx->ossl, peer);
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
    if(peer->sni) {
      WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(ctx->wssl.handle);
      if(wolfSSL_X509_check_host(cert, peer->sni, strlen(peer->sni), 0, NULL)
            == WOLFSSL_FAILURE) {
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
      wolfSSL_X509_free(cert);
    }

  }
#endif
  /* on error, remove any session we might have in the pool */
  if(result)
    Curl_ssl_scache_remove_all(cf, data, peer->scache_key);
  return result;
}


#endif /* !USE_HTTP3 && (USE_OPENSSL || USE_GNUTLS || USE_WOLFSSL) */
