#ifndef HEADER_CURL_NSSG_H
#define HEADER_CURL_NSSG_H
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

#ifdef USE_NSS
/*
 * This header should only be needed to get included by vtls.c and nss.c
 */

#include "urldata.h"

CURLcode Curl_nss_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_nss_connect_nonblocking(struct connectdata *conn,
                                      int sockindex,
                                      bool *done);
/* close a SSL connection */
void Curl_nss_close(struct connectdata *conn, int sockindex);

int Curl_nss_init(void);
void Curl_nss_cleanup(void);

size_t Curl_nss_version(char *buffer, size_t size);
int Curl_nss_check_cxn(struct connectdata *cxn);
int Curl_nss_seed(struct Curl_easy *data);

/* initialize NSS library if not already */
CURLcode Curl_nss_force_init(struct Curl_easy *data);

CURLcode Curl_nss_random(struct Curl_easy *data,
                         unsigned char *entropy,
                         size_t length);

void Curl_nss_sha256sum(const unsigned char *tmp, /* input */
                     size_t tmplen,
                     unsigned char *sha256sum, /* output */
                     size_t sha256len);

bool Curl_nss_cert_status_request(void);

bool Curl_nss_false_start(void);

/* Support HTTPS-proxy */
#define HTTPS_PROXY_SUPPORT 1

extern const struct Curl_ssl Curl_ssl_nss;

/* Set the API backend definition to NSS */
#define CURL_SSL_BACKEND CURLSSLBACKEND_NSS

/* this backend supports the CAPATH option */
#define have_curlssl_ca_path 1

/* this backend supports CURLOPT_CERTINFO */
#define have_curlssl_certinfo 1

/* this backends supports CURLOPT_PINNEDPUBLICKEY */
#define have_curlssl_pinnedpubkey 1

#define curlssl_sha256sum(a,b,c,d) Curl_nss_sha256sum(a,b,c,d)

#endif /* USE_NSS */
#endif /* HEADER_CURL_NSSG_H */
