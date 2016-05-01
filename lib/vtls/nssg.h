#ifndef HEADER_CURL_NSSG_H
#define HEADER_CURL_NSSG_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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
int Curl_nss_seed(struct SessionHandle *data);

/* initialize NSS library if not already */
CURLcode Curl_nss_force_init(struct SessionHandle *data);

int Curl_nss_random(struct SessionHandle *data,
                    unsigned char *entropy,
                    size_t length);

void Curl_nss_md5sum(unsigned char *tmp, /* input */
                     size_t tmplen,
                     unsigned char *md5sum, /* output */
                     size_t md5len);

void Curl_nss_sha256sum(const unsigned char *tmp, /* input */
                     size_t tmplen,
                     unsigned char *sha256sum, /* output */
                     size_t sha256len);

bool Curl_nss_cert_status_request(void);

bool Curl_nss_false_start(void);

/* Set the API backend definition to NSS */
#define CURL_SSL_BACKEND CURLSSLBACKEND_NSS

/* this backend supports the CAPATH option */
#define have_curlssl_ca_path 1

/* this backend supports CURLOPT_CERTINFO */
#define have_curlssl_certinfo 1

/* this backends supports CURLOPT_PINNEDPUBLICKEY */
#define have_curlssl_pinnedpubkey 1

/* API setup for NSS */
#define curlssl_init Curl_nss_init
#define curlssl_cleanup Curl_nss_cleanup
#define curlssl_connect Curl_nss_connect
#define curlssl_connect_nonblocking Curl_nss_connect_nonblocking

/* NSS has its own session ID cache */
#define curlssl_session_free(x) Curl_nop_stmt
#define curlssl_close_all(x) ((void)x)
#define curlssl_close Curl_nss_close
/* NSS has no shutdown function provided and thus always fail */
#define curlssl_shutdown(x,y) ((void)x, (void)y, 1)
#define curlssl_set_engine(x,y) ((void)x, (void)y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) ((void)x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) ((void)x, (struct curl_slist *)NULL)
#define curlssl_version Curl_nss_version
#define curlssl_check_cxn(x) Curl_nss_check_cxn(x)
#define curlssl_data_pending(x,y) ((void)x, (void)y, 0)
#define curlssl_random(x,y,z) Curl_nss_random(x,y,z)
#define curlssl_md5sum(a,b,c,d) Curl_nss_md5sum(a,b,c,d)
#define curlssl_sha256sum(a,b,c,d) Curl_nss_sha256sum(a,b,c,d)
#define curlssl_cert_status_request() Curl_nss_cert_status_request()
#define curlssl_false_start() Curl_nss_false_start()

#endif /* USE_NSS */
#endif /* HEADER_CURL_NSSG_H */
