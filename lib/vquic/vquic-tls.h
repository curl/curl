#ifndef HEADER_CURL_VQUIC_TLS_H
#define HEADER_CURL_VQUIC_TLS_H
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
#include "bufq.h"
#include "vtls/openssl.h"

#if defined(USE_HTTP3) && \
  (defined(USE_OPENSSL) || defined(USE_GNUTLS) || defined(USE_WOLFSSL))

struct curl_tls_ctx {
#ifdef USE_OPENSSL
  struct ossl_ctx ossl;
#elif defined(USE_GNUTLS)
  struct gtls_ctx gtls;
#elif defined(USE_WOLFSSL)
  WOLFSSL_CTX *ssl_ctx;
  WOLFSSL *ssl;
#endif
};

/**
 * Callback passed to `Curl_vquic_tls_init()` that can
 * do early initializations on the not otherwise configured TLS
 * instances created. This varies by TLS backend:
 * - openssl/wolfssl: SSL_CTX* has just been created
 * - gnutls: gtls_client_init() has run
 */
typedef CURLcode Curl_vquic_tls_ctx_setup(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          void *cb_user_data);

/**
 * Initialize the QUIC TLS instances based of the SSL configurations
 * for the connection filter, transfer and peer.
 * @param ctx         the TLS context to initialize
 * @param cf          the connection filter involved
 * @param data        the transfer involved
 * @param peer        the peer that will be connected to
 * @param alpn        the ALPN string in protocol format ((len+bytes+)+),
 *                    may be NULL
 * @param alpn_len    the overall number of bytes in `alpn`
 * @param cb_setup    optional callback for very early TLS config
 ± @param cb_user_data user_data param for callback
 * @param ssl_user_data  optional pointer to set in TLS application context
 */
CURLcode Curl_vquic_tls_init(struct curl_tls_ctx *ctx,
                             struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct ssl_peer *peer,
                             const char *alpn, size_t alpn_len,
                             Curl_vquic_tls_ctx_setup *cb_setup,
                             void *cb_user_data,
                             void *ssl_user_data);

/**
 * Cleanup all data that has been initialized.
 */
void Curl_vquic_tls_cleanup(struct curl_tls_ctx *ctx);

CURLcode Curl_vquic_tls_before_recv(struct curl_tls_ctx *ctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data);

/**
 * After the QUIC basic handshake has been, verify that the peer
 * (and its certificate) fulfill our requirements.
 */
CURLcode Curl_vquic_tls_verify_peer(struct curl_tls_ctx *ctx,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ssl_peer *peer);

#endif /* !USE_HTTP3 && (USE_OPENSSL || USE_GNUTLS || USE_WOLFSSL) */

#endif /* HEADER_CURL_VQUIC_TLS_H */
