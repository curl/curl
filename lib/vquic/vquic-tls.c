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

#if defined(ENABLE_QUIC) && \
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
#include "vquic-tls.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#ifdef USE_OPENSSL
#define QUIC_CIPHERS                                                          \
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"               \
  "POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define QUIC_GROUPS "P-256:X25519:P-384:P-521"
#elif defined(USE_GNUTLS)
#define QUIC_PRIORITY \
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:" \
  "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:" \
  "+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
  "%DISABLE_TLS13_COMPAT_MODE"
#elif defined(USE_WOLFSSL)
#define QUIC_CIPHERS                                                          \
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"               \
  "POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define QUIC_GROUPS "P-256:P-384:P-521"
#endif


#ifdef USE_OPENSSL

static void keylog_callback(const SSL *ssl, const char *line)
{
  (void)ssl;
  Curl_tls_keylog_write_line(line);
}

static CURLcode curl_ossl_init_ctx(struct quic_tls_ctx *ctx,
                                   struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   Curl_vquic_tls_ctx_setup *ctx_setup)
{
  struct ssl_primary_config *conn_config;
  CURLcode result = CURLE_FAILED_INIT;

  DEBUGASSERT(!ctx->ssl_ctx);
#ifdef USE_OPENSSL_QUIC
  ctx->ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
#else
  ctx->ssl_ctx = SSL_CTX_new(TLS_method());
#endif
  if(!ctx->ssl_ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!conn_config) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  if(ctx_setup) {
    result = ctx_setup(ctx, cf, data);
    if(result)
      goto out;
  }

  SSL_CTX_set_default_verify_paths(ctx->ssl_ctx);

  {
    const char *curves = conn_config->curves ?
      conn_config->curves : QUIC_GROUPS;
    if(!SSL_CTX_set1_curves_list(ctx->ssl_ctx, curves)) {
      failf(data, "failed setting curves list for QUIC: '%s'", curves);
      return CURLE_SSL_CIPHER;
    }
  }

#ifndef OPENSSL_IS_BORINGSSL
  {
    const char *ciphers13 = conn_config->cipher_list13 ?
      conn_config->cipher_list13 : QUIC_CIPHERS;
    if(SSL_CTX_set_ciphersuites(ctx->ssl_ctx, ciphers13) != 1) {
      failf(data, "failed setting QUIC cipher suite: %s", ciphers13);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "QUIC cipher selection: %s", ciphers13);
  }
#endif

  /* Open the file if a TLS or QUIC backend has not done this before. */
  Curl_tls_keylog_open();
  if(Curl_tls_keylog_enabled()) {
    SSL_CTX_set_keylog_callback(ctx->ssl_ctx, keylog_callback);
  }

  /* OpenSSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
  SSL_CTX_set_verify(ctx->ssl_ctx, conn_config->verifypeer ?
                     SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    /* When a user callback is installed to modify the SSL_CTX,
     * we need to do the full initialization before calling it.
     * See: #11800 */
    if(!ctx->x509_store_setup) {
      result = Curl_ssl_setup_x509_store(cf, data, ctx->ssl_ctx);
      if(result)
        goto out;
      ctx->x509_store_setup = TRUE;
    }
    Curl_set_in_callback(data, true);
    result = (*data->set.ssl.fsslctx)(data, ctx->ssl_ctx,
                                      data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, false);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      goto out;
    }
  }
  result = CURLE_OK;

out:
  if(result && ctx->ssl_ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
    ctx->ssl_ctx = NULL;
  }
  return result;
}

static CURLcode curl_ossl_set_client_cert(struct quic_tls_ctx *ctx,
                                     struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  SSL_CTX *ssl_ctx = ctx->ssl_ctx;
  const struct ssl_config_data *ssl_config;

  ssl_config = Curl_ssl_cf_get_config(cf, data);
  DEBUGASSERT(ssl_config);

  if(ssl_config->primary.clientcert ||
     ssl_config->primary.cert_blob ||
     ssl_config->cert_type) {
    return Curl_ossl_set_client_cert(
        data, ssl_ctx, ssl_config->primary.clientcert,
        ssl_config->primary.cert_blob, ssl_config->cert_type,
        ssl_config->key, ssl_config->key_blob,
        ssl_config->key_type, ssl_config->key_passwd);
  }

  return CURLE_OK;
}

/** SSL callbacks ***/

static CURLcode curl_ossl_init_ssl(struct quic_tls_ctx *ctx,
                                   struct Curl_easy *data,
                                   struct ssl_peer *peer,
                                   const char *alpn, size_t alpn_len,
                                   void *user_data)
{
  DEBUGASSERT(!ctx->ssl);
  ctx->ssl = SSL_new(ctx->ssl_ctx);

  SSL_set_app_data(ctx->ssl, user_data);
  SSL_set_connect_state(ctx->ssl);
#ifndef USE_OPENSSL_QUIC
  SSL_set_quic_use_legacy_codepoint(ctx->ssl, 0);
#endif

  if(alpn)
    SSL_set_alpn_protos(ctx->ssl, (const uint8_t *)alpn, (int)alpn_len);

  if(peer->sni) {
    if(!SSL_set_tlsext_host_name(ctx->ssl, peer->sni)) {
      failf(data, "Failed set SNI");
      SSL_free(ctx->ssl);
      ctx->ssl = NULL;
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }
  return CURLE_OK;
}

#elif defined(USE_GNUTLS)
static int keylog_callback(gnutls_session_t session, const char *label,
                    const gnutls_datum_t *secret)
{
  gnutls_datum_t crandom;
  gnutls_datum_t srandom;

  gnutls_session_get_random(session, &crandom, &srandom);
  if(crandom.size != 32) {
    return -1;
  }

  Curl_tls_keylog_write(label, crandom.data, secret->data, secret->size);
  return 0;
}

static CURLcode curl_gtls_init_ctx(struct quic_tls_ctx *ctx,
                                   struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct ssl_peer *peer,
                                   const char *alpn, size_t alpn_len,
                                   Curl_vquic_tls_ctx_setup *ctx_setup,
                                   void *user_data)
{
  struct ssl_primary_config *conn_config;
  CURLcode result;
  gnutls_datum_t alpns[5];
  /* this will need some attention when HTTPS proxy over QUIC get fixed */
  long * const pverifyresult = &data->set.ssl.certverifyresult;
  int rc;

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!conn_config)
    return CURLE_FAILED_INIT;

  DEBUGASSERT(ctx->gtls == NULL);
  ctx->gtls = calloc(1, sizeof(*(ctx->gtls)));
  if(!ctx->gtls)
    return CURLE_OUT_OF_MEMORY;

  result = gtls_client_init(data, conn_config, &data->set.ssl,
                            peer, ctx->gtls, pverifyresult);
  if(result)
    return result;

  gnutls_session_set_ptr(ctx->gtls->session, user_data);

  if(ctx_setup) {
    result = ctx_setup(ctx, cf, data);
    if(result)
      return result;
  }

  rc = gnutls_priority_set_direct(ctx->gtls->session, QUIC_PRIORITY, NULL);
  if(rc < 0) {
    CURL_TRC_CF(data, cf, "gnutls_priority_set_direct failed: %s\n",
                gnutls_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  /* Open the file if a TLS or QUIC backend has not done this before. */
  Curl_tls_keylog_open();
  if(Curl_tls_keylog_enabled()) {
    gnutls_session_set_keylog_function(ctx->gtls->session, keylog_callback);
  }

  /* convert the ALPN string from our arguments to a list of strings
   * that gnutls wants and will convert internally back to this very
   * string for sending to the server. nice. */
  if(alpn) {
    size_t i, alen = alpn_len;
    unsigned char *s = (unsigned char *)alpn;
    unsigned char slen;
    for(i = 0; (i < ARRAYSIZE(alpns)) && alen; ++i) {
      slen = s[0];
      if(slen >= alen)
        return CURLE_FAILED_INIT;
      alpns[i].data = s + 1;
      alpns[i].size = slen;
      s += slen + 1;
      alen -= (size_t)slen + 1;
    }
    if(alen) /* not all alpn chars used, wrong format or too many */
        return CURLE_FAILED_INIT;
    if(i) {
      gnutls_alpn_set_protocols(ctx->gtls->session,
                                alpns, (unsigned int)i,
                                GNUTLS_ALPN_MANDATORY);
    }
  }

  return CURLE_OK;
}
#elif defined(USE_WOLFSSL)

#if defined(HAVE_SECRET_CALLBACK)
static void keylog_callback(const WOLFSSL *ssl, const char *line)
{
  (void)ssl;
  Curl_tls_keylog_write_line(line);
}
#endif

static CURLcode curl_wssl_init_ctx(struct quic_tls_ctx *ctx,
                                   struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   Curl_vquic_tls_ctx_setup *ctx_setup)
{
  struct ssl_primary_config *conn_config;
  CURLcode result = CURLE_FAILED_INIT;

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!conn_config) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  ctx->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  if(!ctx->ssl_ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(ctx_setup) {
    result = ctx_setup(ctx, cf, data);
    if(result)
      goto out;
  }

  wolfSSL_CTX_set_default_verify_paths(ctx->ssl_ctx);

  if(wolfSSL_CTX_set_cipher_list(ctx->ssl_ctx, conn_config->cipher_list13 ?
                                 conn_config->cipher_list13 :
                                 QUIC_CIPHERS) != 1) {
    char error_buffer[256];
    ERR_error_string_n(ERR_get_error(), error_buffer, sizeof(error_buffer));
    failf(data, "wolfSSL failed to set ciphers: %s", error_buffer);
    goto out;
  }

  if(wolfSSL_CTX_set1_groups_list(ctx->ssl_ctx, conn_config->curves ?
                                  conn_config->curves :
                                  (char *)QUIC_GROUPS) != 1) {
    failf(data, "wolfSSL failed to set curves");
    goto out;
  }

  /* Open the file if a TLS or QUIC backend has not done this before. */
  Curl_tls_keylog_open();
  if(Curl_tls_keylog_enabled()) {
#if defined(HAVE_SECRET_CALLBACK)
    wolfSSL_CTX_set_keylog_callback(ctx->ssl_ctx, keylog_callback);
#else
    failf(data, "wolfSSL was built without keylog callback");
    goto out;
#endif
  }

  if(conn_config->verifypeer) {
    const char * const ssl_cafile = conn_config->CAfile;
    const char * const ssl_capath = conn_config->CApath;

    wolfSSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
    if(ssl_cafile || ssl_capath) {
      /* tell wolfSSL where to find CA certificates that are used to verify
         the server's certificate. */
      int rc =
        wolfSSL_CTX_load_verify_locations_ex(ctx->ssl_ctx, ssl_cafile,
                                             ssl_capath,
                                             WOLFSSL_LOAD_FLAG_IGNORE_ERR);
      if(SSL_SUCCESS != rc) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data, "error setting certificate verify locations:"
              "  CAfile: %s CApath: %s",
              ssl_cafile ? ssl_cafile : "none",
              ssl_capath ? ssl_capath : "none");
        goto out;
      }
      infof(data, " CAfile: %s", ssl_cafile ? ssl_cafile : "none");
      infof(data, " CApath: %s", ssl_capath ? ssl_capath : "none");
    }
#ifdef CURL_CA_FALLBACK
    else {
      /* verifying the peer without any CA certificates won't work so
         use wolfssl's built-in default as fallback */
      wolfSSL_CTX_set_default_verify_paths(ctx->ssl_ctx);
    }
#endif
  }
  else {
    wolfSSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
  }

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    Curl_set_in_callback(data, true);
    result = (*data->set.ssl.fsslctx)(data, ctx->ssl_ctx,
                                      data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, false);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      goto out;
    }
  }
  result = CURLE_OK;

out:
  if(result && ctx->ssl_ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
    ctx->ssl_ctx = NULL;
  }
  return result;
}

/** SSL callbacks ***/

static CURLcode curl_wssl_init_ssl(struct quic_tls_ctx *ctx,
                                   struct Curl_easy *data,
                                   struct ssl_peer *peer,
                                   const char *alpn, size_t alpn_len,
                                   void *user_data)
{
  (void)data;
  DEBUGASSERT(!ctx->ssl);
  DEBUGASSERT(ctx->ssl_ctx);
  ctx->ssl = wolfSSL_new(ctx->ssl_ctx);

  wolfSSL_set_app_data(ctx->ssl, user_data);
  wolfSSL_set_connect_state(ctx->ssl);
  wolfSSL_set_quic_use_legacy_codepoint(ctx->ssl, 0);

  if(alpn)
    wolfSSL_set_alpn_protos(ctx->ssl, (const unsigned char *)alpn,
                            (int)alpn_len);

  if(peer->sni) {
    wolfSSL_UseSNI(ctx->ssl, WOLFSSL_SNI_HOST_NAME,
                   peer->sni, (unsigned short)strlen(peer->sni));
  }

  return CURLE_OK;
}
#endif /* defined(USE_WOLFSSL) */

CURLcode Curl_vquic_tls_init(struct quic_tls_ctx *ctx,
                             struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct ssl_peer *peer,
                             const char *alpn, size_t alpn_len,
                             Curl_vquic_tls_ctx_setup *ctx_setup,
                             void *user_data)
{
  CURLcode result;

#ifdef USE_OPENSSL
  result = curl_ossl_init_ctx(ctx, cf, data, ctx_setup);
  if(result)
    return result;

  result = curl_ossl_set_client_cert(ctx, cf, data);
  if(result)
    return result;

  return curl_ossl_init_ssl(ctx, data, peer, alpn, alpn_len, user_data);
#elif defined(USE_GNUTLS)
  (void)result;
  return curl_gtls_init_ctx(ctx, cf, data, peer, alpn, alpn_len,
                            ctx_setup, user_data);
#elif defined(USE_WOLFSSL)
  result = curl_wssl_init_ctx(ctx, cf, data, ctx_setup);
  if(result)
    return result;

  return curl_wssl_init_ssl(ctx, data, peer, alpn, alpn_len, user_data);
#else
#error "no TLS lib in used, should not happen"
  return CURLE_FAILED_INIT;
#endif
}

void Curl_vquic_tls_cleanup(struct quic_tls_ctx *ctx)
{
#ifdef USE_OPENSSL
  if(ctx->ssl)
    SSL_free(ctx->ssl);
  if(ctx->ssl_ctx)
    SSL_CTX_free(ctx->ssl_ctx);
#elif defined(USE_GNUTLS)
  if(ctx->gtls) {
    if(ctx->gtls->cred)
      gnutls_certificate_free_credentials(ctx->gtls->cred);
    if(ctx->gtls->session)
      gnutls_deinit(ctx->gtls->session);
    free(ctx->gtls);
  }
#elif defined(USE_WOLFSSL)
  if(ctx->ssl)
    wolfSSL_free(ctx->ssl);
  if(ctx->ssl_ctx)
    wolfSSL_CTX_free(ctx->ssl_ctx);
#endif
  memset(ctx, 0, sizeof(*ctx));
}

CURLcode Curl_vquic_tls_before_recv(struct quic_tls_ctx *ctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
#ifdef USE_OPENSSL
  if(!ctx->x509_store_setup) {
    CURLcode result = Curl_ssl_setup_x509_store(cf, data, ctx->ssl_ctx);
    if(result)
      return result;
    ctx->x509_store_setup = TRUE;
  }
#else
  (void)ctx; (void)cf; (void)data;
#endif
  return CURLE_OK;
}

CURLcode Curl_vquic_tls_verify_peer(struct quic_tls_ctx *ctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ssl_peer *peer)
{
  struct ssl_primary_config *conn_config;
  CURLcode result = CURLE_OK;

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!conn_config)
    return CURLE_FAILED_INIT;

  if(conn_config->verifyhost) {
#ifdef USE_OPENSSL
    X509 *server_cert;
    server_cert = SSL_get1_peer_certificate(ctx->ssl);
    if(!server_cert) {
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    result = Curl_ossl_verifyhost(data, cf->conn, peer, server_cert);
    X509_free(server_cert);
    if(result)
      return result;
#elif defined(USE_GNUTLS)
    result = Curl_gtls_verifyserver(data, ctx->gtls->session,
                                    conn_config, &data->set.ssl, peer,
                                    data->set.str[STRING_SSL_PINNEDPUBLICKEY]);
    if(result)
      return result;
#elif defined(USE_WOLFSSL)
    if(!peer->sni ||
       wolfSSL_check_domain_name(ctx->ssl, peer->sni) == SSL_FAILURE)
      return CURLE_PEER_FAILED_VERIFICATION;
#endif
    infof(data, "Verified certificate just fine");
  }
  else
    infof(data, "Skipped certificate verification");
#ifdef USE_OPENSSL
  if(data->set.ssl.certinfo)
    /* asked to gather certificate info */
    (void)Curl_ossl_certchain(data, ctx->ssl);
#endif
  return result;
}


#endif /* !ENABLE_QUIC && (USE_OPENSSL || USE_GNUTLS || USE_WOLFSSL) */
