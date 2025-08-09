#ifndef HEADER_CURL_VQUIC_QUIC_H
#define HEADER_CURL_VQUIC_QUIC_H
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

#include "../curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)
struct Curl_cfilter;
struct Curl_easy;
struct connectdata;
struct Curl_addrinfo;

void Curl_quic_ver(char *p, size_t len);
int Curl_vquic_init(void);

CURLcode Curl_qlogdir(struct Curl_easy *data,
                      unsigned char *scid,
                      size_t scidlen,
                      int *qlogfdp);


CURLcode Curl_cf_quic_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             const struct Curl_addrinfo *ai,
                             int transport);

extern struct Curl_cftype Curl_cft_http3;

#if defined(USE_NGTCP2) || defined(USE_NGHTTP3)

void *Curl_ngtcp2_malloc(size_t size, void *user_data);
void Curl_ngtcp2_free(void *ptr, void *user_data);
void *Curl_ngtcp2_calloc(size_t nmemb, size_t size, void *user_data);
void *Curl_ngtcp2_realloc(void *ptr, size_t size, void *user_data);

#ifdef USE_NGTCP2
void *Curl_ngtcp2_mem(void);
#endif
#ifdef USE_NGHTTP3
void *Curl_nghttp3_mem(void);
#endif

#endif /* USE_NGTCP2 || USE_NGHTTP3 */

#else
#define Curl_vquic_init() 1
#endif /* !CURL_DISABLE_HTTP && USE_HTTP3 */

CURLcode Curl_conn_may_http3(struct Curl_easy *data,
                             const struct connectdata *conn,
                             unsigned char transport);

#endif /* HEADER_CURL_VQUIC_QUIC_H */
