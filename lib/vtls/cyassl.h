#ifndef HEADER_CURL_CYASSL_H
#define HEADER_CURL_CYASSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_CYASSL

/* KEEP_PEER_CERT is a product of the presence of build time symbol
   OPENSSL_EXTRA without NO_CERTS, depending on the version. KEEP_PEER_CERT is
   in wolfSSL's settings.h, and the latter two are build time symbols in
   options.h. */
#ifndef KEEP_PEER_CERT
#if defined(HAVE_CYASSL_GET_PEER_CERTIFICATE) || \
    defined(HAVE_WOLFSSL_GET_PEER_CERTIFICATE) || \
    (defined(OPENSSL_EXTRA) && !defined(NO_CERTS))
#define KEEP_PEER_CERT
#endif
#endif

CURLcode Curl_cyassl_connect(struct connectdata *conn, int sockindex);
bool Curl_cyassl_data_pending(const struct connectdata* conn, int connindex);
int Curl_cyassl_shutdown(struct connectdata* conn, int sockindex);

 /* close a SSL connection */
void Curl_cyassl_close(struct connectdata *conn, int sockindex);

void Curl_cyassl_session_free(void *ptr);
size_t Curl_cyassl_version(char *buffer, size_t size);
int Curl_cyassl_shutdown(struct connectdata *conn, int sockindex);
int Curl_cyassl_init(void);
CURLcode Curl_cyassl_connect_nonblocking(struct connectdata *conn,
                                         int sockindex,
                                         bool *done);
CURLcode Curl_cyassl_random(struct Curl_easy *data,
                            unsigned char *entropy,
                            size_t length);

extern const struct Curl_ssl Curl_ssl_cyassl;

/* Set the API backend definition to CyaSSL */
#define CURL_SSL_BACKEND CURLSSLBACKEND_CYASSL

/* this backend supports CURLOPT_SSL_CTX_* */
#define have_curlssl_ssl_ctx 1

#ifdef KEEP_PEER_CERT
/* this backend supports CURLOPT_PINNEDPUBLICKEY */
#define have_curlssl_pinnedpubkey 1
#endif

#endif /* USE_CYASSL */
#endif /* HEADER_CURL_CYASSL_H */
