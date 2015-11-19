#ifndef HEADER_CURL_CYASSL_H
#define HEADER_CURL_CYASSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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
int Curl_cyassl_random(struct SessionHandle *data,
                       unsigned char *entropy,
                       size_t length);
void Curl_cyassl_sha256sum(const unsigned char *tmp, /* input */
                     size_t tmplen,
                     unsigned char *sha256sum, /* output */
                     size_t unused);

/* Set the API backend definition to Schannel */
#define CURL_SSL_BACKEND CURLSSLBACKEND_CYASSL

/* this backend supports CURLOPT_SSL_CTX_* */
#define have_curlssl_ssl_ctx 1

/* API setup for CyaSSL */
#define curlssl_init Curl_cyassl_init
#define curlssl_cleanup() Curl_nop_stmt
#define curlssl_connect Curl_cyassl_connect
#define curlssl_connect_nonblocking Curl_cyassl_connect_nonblocking
#define curlssl_session_free(x)  Curl_cyassl_session_free(x)
#define curlssl_close_all(x) ((void)x)
#define curlssl_close Curl_cyassl_close
#define curlssl_shutdown(x,y) Curl_cyassl_shutdown(x,y)
#define curlssl_set_engine(x,y) ((void)x, (void)y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) ((void)x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) ((void)x, (struct curl_slist *)NULL)
#define curlssl_version Curl_cyassl_version
#define curlssl_check_cxn(x) ((void)x, -1)
#define curlssl_data_pending(x,y) Curl_cyassl_data_pending(x,y)
#define curlssl_random(x,y,z) Curl_cyassl_random(x,y,z)
#define curlssl_sha256sum(a,b,c,d) Curl_cyassl_sha256sum(a,b,c,d)

#endif /* USE_CYASSL */
#endif /* HEADER_CURL_CYASSL_H */
