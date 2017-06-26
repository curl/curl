#ifndef HEADER_CURL_GTLS_H
#define HEADER_CURL_GTLS_H
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

#ifdef USE_GNUTLS

#include "urldata.h"

int Curl_gtls_init(void);
void Curl_gtls_cleanup(void);
CURLcode Curl_gtls_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_gtls_connect_nonblocking(struct connectdata *conn,
                                       int sockindex,
                                       bool *done);
bool Curl_gtls_data_pending(const struct connectdata *conn,
                            int connindex);

 /* close a SSL connection */
void Curl_gtls_close(struct connectdata *conn, int sockindex);

void Curl_gtls_session_free(void *ptr);
size_t Curl_gtls_version(char *buffer, size_t size);
int Curl_gtls_shutdown(struct connectdata *conn, int sockindex);
CURLcode Curl_gtls_random(struct Curl_easy *data,
                          unsigned char *entropy,
                          size_t length);

bool Curl_gtls_cert_status_request(void);

extern const struct Curl_ssl Curl_ssl_gnutls;

/* Set the API backend definition to GnuTLS */
#define CURL_SSL_BACKEND CURLSSLBACKEND_GNUTLS

#endif /* USE_GNUTLS */
#endif /* HEADER_CURL_GTLS_H */
