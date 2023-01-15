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
#include <openssl/ssl.h>

#include "urldata.h"

/*
 * In an effort to avoid using 'X509 *' here, we instead use the struct
 * x509_st version of the type so that we can forward-declare it here without
 * having to include <openssl/x509v3.h>. Including that header causes name
 * conflicts when libcurl is built with both Schannel and OpenSSL support.
 */
struct x509_st;
CURLcode Curl_ossl_verifyhost(struct Curl_easy *data, struct connectdata *conn,
                              struct x509_st *server_cert);
extern const struct Curl_ssl Curl_ssl_openssl;

struct ssl_ctx_st;
CURLcode Curl_ossl_set_client_cert(struct Curl_easy *data,
                                   struct ssl_ctx_st *ctx, char *cert_file,
                                   const struct curl_blob *cert_blob,
                                   const char *cert_type, char *key_file,
                                   const struct curl_blob *key_blob,
                                   const char *key_type, char *key_passwd);

CURLcode Curl_ossl_certchain(struct Curl_easy *data, SSL *ssl);

/**
 * Setup the OpenSSL X509_STORE in `ssl_ctx` for the cfilter `cf` and
 * easy handle `data`. Will allow reuse of a shared cache if suitable
 * and configured.
 */
CURLcode Curl_ssl_setup_x509_store(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   SSL_CTX *ssl_ctx);

#endif /* USE_OPENSSL */
#endif /* HEADER_CURL_SSLUSE_H */
