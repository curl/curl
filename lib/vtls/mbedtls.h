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

/* Called on first use mbedTLS, setup threading if supported */
int  Curl_mbedtls_init(void);
void Curl_mbedtls_cleanup(void);
bool Curl_mbedtls_data_pending(const struct connectdata *conn, int sockindex);

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

extern const struct Curl_ssl Curl_ssl_mbedtls;

#define CURL_SSL_BACKEND CURLSSLBACKEND_MBEDTLS

#endif /* USE_MBEDTLS */
#endif /* HEADER_CURL_MBEDTLS_H */
