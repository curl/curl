#ifndef HEADER_CURL_SSLUSE_H
#define HEADER_CURL_SSLUSE_H
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

#ifdef USE_OPENSSL
/*
 * This header should only be needed to get included by vtls.c, openssl.c
 * and ngtcp2.c
 */
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>

#include "urldata.h"

/*
 * Whether SSL_CTX_set_keylog_callback is available.
 * OpenSSL: supported since 1.1.1 https://github.com/openssl/openssl/pull/2287
 * BoringSSL: supported since d28f59c27bac (committed 2015-11-19)
 * LibreSSL: not supported. 3.5.0+ has a stub function that does nothing.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L && \
     !defined(LIBRESSL_VERSION_NUMBER)) || \
    defined(OPENSSL_IS_BORINGSSL)
#define HAVE_KEYLOG_CALLBACK
#endif

struct ssl_peer;

/* Struct to hold a curl OpenSSL instance */
struct ossl_ctx {
  /* these ones requires specific SSL-types */
  SSL_CTX* ssl_ctx;
  SSL*     ssl;
  X509*    server_cert;
  BIO_METHOD *bio_method;
  CURLcode io_result;       /* result of last BIO cfilter operation */
#ifndef HAVE_KEYLOG_CALLBACK
  /* Set to true once a valid keylog entry has been created to avoid dupes.
     This is a bool and not a bitfield because it is passed by address. */
  bool keylog_done;
#endif
  BIT(x509_store_setup);            /* x509 store has been set up */
  BIT(reused_session);              /* session-ID was reused for this */
};

size_t Curl_ossl_version(char *buffer, size_t size);

typedef CURLcode Curl_ossl_ctx_setup_cb(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        void *user_data);

typedef int Curl_ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid);

CURLcode Curl_ossl_ctx_init(struct ossl_ctx *octx,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct ssl_peer *peer,
                            const unsigned char *alpn, size_t alpn_len,
                            Curl_ossl_ctx_setup_cb *cb_setup,
                            void *cb_user_data,
                            Curl_ossl_new_session_cb *cb_new_session,
                            void *ssl_user_data);

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

extern const struct Curl_ssl Curl_ssl_openssl;

/**
 * Setup the OpenSSL X509_STORE in `ssl_ctx` for the cfilter `cf` and
 * easy handle `data`. Will allow reuse of a shared cache if suitable
 * and configured.
 */
CURLcode Curl_ssl_setup_x509_store(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   SSL_CTX *ssl_ctx);

CURLcode Curl_ossl_ctx_configure(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 SSL_CTX *ssl_ctx);

/*
 * Add a new session to the cache. Takes ownership of the session.
 */
CURLcode Curl_ossl_add_session(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const char *ssl_peer_key,
                               SSL_SESSION *ssl_sessionid,
                               int ietf_tls_id,
                               const char *alpn);

/*
 * Get the server cert, verify it and show it, etc., only call failf() if
 * ssl config verifypeer or -host is set. Otherwise all this is for
 * informational purposes only!
 */
CURLcode Curl_oss_check_peer_cert(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct ossl_ctx *octx,
                                  struct ssl_peer *peer);

#endif /* USE_OPENSSL */
#endif /* HEADER_CURL_SSLUSE_H */
