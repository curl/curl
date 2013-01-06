#ifndef HEADER_CURL_DARWINSSL_H
#define HEADER_CURL_DARWINSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Nick Zitzmann, <nickzman@gmail.com>.
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

#ifdef USE_DARWINSSL

CURLcode Curl_darwinssl_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_darwinssl_connect_nonblocking(struct connectdata *conn,
                                            int sockindex,
                                            bool *done);

/* this function doesn't actually do anything */
void Curl_darwinssl_close_all(struct SessionHandle *data);

/* close a SSL connection */
void Curl_darwinssl_close(struct connectdata *conn, int sockindex);

size_t Curl_darwinssl_version(char *buffer, size_t size);
int Curl_darwinssl_shutdown(struct connectdata *conn, int sockindex);
int Curl_darwinssl_check_cxn(struct connectdata *conn);
bool Curl_darwinssl_data_pending(const struct connectdata *conn,
                                 int connindex);

void Curl_darwinssl_random(struct SessionHandle *data,
                           unsigned char *entropy,
                           size_t length);
void Curl_darwinssl_md5sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *md5sum, /* output */
                           size_t md5len);

/* API setup for SecureTransport */
#define curlssl_init() (1)
#define curlssl_cleanup() Curl_nop_stmt
#define curlssl_connect Curl_darwinssl_connect
#define curlssl_connect_nonblocking Curl_darwinssl_connect_nonblocking
#define curlssl_session_free(x) Curl_nop_stmt
#define curlssl_close_all Curl_darwinssl_close_all
#define curlssl_close Curl_darwinssl_close
#define curlssl_shutdown(x,y) 0
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) (x=x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_version Curl_darwinssl_version
#define curlssl_check_cxn Curl_darwinssl_check_cxn
#define curlssl_data_pending(x,y) Curl_darwinssl_data_pending(x, y)
#define curlssl_random(x,y,z) Curl_darwinssl_random(x,y,z)
#define curlssl_md5sum(a,b,c,d) Curl_darwinssl_md5sum(a,b,c,d)

#endif /* USE_DARWINSSL */
#endif /* HEADER_CURL_DARWINSSL_H */
