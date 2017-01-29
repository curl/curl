#ifndef HEADER_CURL_MBEDTLS_H
#define HEADER_CURL_MBEDTLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2010, Hoi-Ho Chan, <hoiho.chan@gmail.com>
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

#ifdef USE_MBEDTLS

#include <mbedtls/sha256.h>

/* Called on first use mbedTLS, setup threading if supported */
int  Curl_mbedtls_init(void);
void Curl_mbedtls_cleanup(void);
int Curl_mbedtls_data_pending(const struct connectdata *conn, int sockindex);

CURLcode Curl_mbedtls_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_mbedtls_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done);

/* tell mbedTLS to close down all open information regarding connections (and
   thus session ID caching etc) */
void Curl_mbedtls_close_all(struct Curl_easy *data);

 /* close a SSL connection */
void Curl_mbedtls_close(struct connectdata *conn, int sockindex);

void Curl_mbedtls_session_free(void *ptr);
size_t Curl_mbedtls_version(char *buffer, size_t size);
int Curl_mbedtls_shutdown(struct connectdata *conn, int sockindex);

CURLcode Curl_mbedtls_random(struct Curl_easy *data, unsigned char *entropy,
                     size_t length);

/* this backends supports CURLOPT_PINNEDPUBLICKEY */
#define have_curlssl_pinnedpubkey 1

/* API setup for mbedTLS */
#define curlssl_init() Curl_mbedtls_init()
#define curlssl_cleanup() Curl_mbedtls_cleanup()
#define curlssl_connect Curl_mbedtls_connect
#define curlssl_connect_nonblocking Curl_mbedtls_connect_nonblocking
#define curlssl_session_free(x)  Curl_mbedtls_session_free(x)
#define curlssl_close_all Curl_mbedtls_close_all
#define curlssl_close Curl_mbedtls_close
#define curlssl_shutdown(x,y) 0
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) (x=x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_version Curl_mbedtls_version
#define curlssl_check_cxn(x) (x=x, -1)
#define curlssl_data_pending(x,y) Curl_mbedtls_data_pending(x, y)
#define CURL_SSL_BACKEND CURLSSLBACKEND_MBEDTLS
#define curlssl_sha256sum(a,b,c,d) mbedtls_sha256(a,b,c,0)
#define curlssl_random(x,y,z) Curl_mbedtls_random(x, y, z)

#endif /* USE_MBEDTLS */
#endif /* HEADER_CURL_MBEDTLS_H */
