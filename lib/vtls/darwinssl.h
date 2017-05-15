#ifndef HEADER_CURL_DARWINSSL_H
#define HEADER_CURL_DARWINSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2014, Nick Zitzmann, <nickzman@gmail.com>.
 * Copyright (C) 2012 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef USE_DARWINSSL

CURLcode Curl_darwinssl_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_darwinssl_connect_nonblocking(struct connectdata *conn,
                                            int sockindex,
                                            bool *done);

/* close a SSL connection */
void Curl_darwinssl_close(struct connectdata *conn, int sockindex);

void Curl_darwinssl_session_free(void *ptr);
size_t Curl_darwinssl_version(char *buffer, size_t size);
int Curl_darwinssl_shutdown(struct connectdata *conn, int sockindex);
int Curl_darwinssl_check_cxn(struct connectdata *conn);
bool Curl_darwinssl_data_pending(const struct connectdata *conn,
                                 int connindex);

CURLcode Curl_darwinssl_random(unsigned char *entropy,
                               size_t length);
void Curl_darwinssl_md5sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *md5sum, /* output */
                           size_t md5len);
void Curl_darwinssl_sha256sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *sha256sum, /* output */
                           size_t sha256len);
bool Curl_darwinssl_false_start(void);

/* Set the API backend definition to SecureTransport */
#define CURL_SSL_BACKEND CURLSSLBACKEND_DARWINSSL

/* pinned public key support tests */

/* version 1 supports macOS 10.12+ and iOS 10+ */
#if ((TARGET_OS_IPHONE && __IPHONE_OS_VERSION_MIN_REQUIRED >= 100000) || \
    (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED  >= 101200))
#define DARWIN_SSL_PINNEDPUBKEY_V1 1
#endif

/* version 2 supports MacOSX 10.7+ */
#if (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070)
#define DARWIN_SSL_PINNEDPUBKEY_V2 1
#endif

#if defined(DARWIN_SSL_PINNEDPUBKEY_V1) || defined(DARWIN_SSL_PINNEDPUBKEY_V2)
/* this backend supports CURLOPT_PINNEDPUBLICKEY */
#define DARWIN_SSL_PINNEDPUBKEY 1
#define have_curlssl_pinnedpubkey 1
#endif /* DARWIN_SSL_PINNEDPUBKEY */

/* API setup for SecureTransport */
#define curlssl_init() (1)
#define curlssl_cleanup() Curl_nop_stmt
#define curlssl_connect Curl_darwinssl_connect
#define curlssl_connect_nonblocking Curl_darwinssl_connect_nonblocking
#define curlssl_session_free(x) Curl_darwinssl_session_free(x)
#define curlssl_close_all(x) ((void)x)
#define curlssl_close Curl_darwinssl_close
#define curlssl_shutdown(x,y) 0
#define curlssl_set_engine(x,y) ((void)x, (void)y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) ((void)x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) ((void)x, (struct curl_slist *)NULL)
#define curlssl_version Curl_darwinssl_version
#define curlssl_check_cxn Curl_darwinssl_check_cxn
#define curlssl_data_pending(x,y) Curl_darwinssl_data_pending(x, y)
#define curlssl_random(x,y,z) ((void)x, Curl_darwinssl_random(y,z))
#define curlssl_md5sum(a,b,c,d) Curl_darwinssl_md5sum(a,b,c,d)
#define curlssl_sha256sum(a,b,c,d) Curl_darwinssl_sha256sum(a,b,c,d)
#define curlssl_false_start() Curl_darwinssl_false_start()

#endif /* USE_DARWINSSL */
#endif /* HEADER_CURL_DARWINSSL_H */
