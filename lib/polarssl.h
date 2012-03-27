#ifndef HEADER_CURL_POLARSSL_H
#define HEADER_CURL_POLARSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, Hoi-Ho Chan, <hoiho.chan@gmail.com>
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
#include "setup.h"

#ifdef USE_POLARSSL

CURLcode Curl_polarssl_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_polarssl_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done);

/* tell PolarSSL to close down all open information regarding connections (and
   thus session ID caching etc) */
void Curl_polarssl_close_all(struct SessionHandle *data);

 /* close a SSL connection */
void Curl_polarssl_close(struct connectdata *conn, int sockindex);

void Curl_polarssl_session_free(void *ptr);
size_t Curl_polarssl_version(char *buffer, size_t size);
int Curl_polarssl_shutdown(struct connectdata *conn, int sockindex);

/* API setup for PolarSSL */
#define curlssl_init() (1)
#define curlssl_cleanup() Curl_nop_stmt
#define curlssl_connect Curl_polarssl_connect
#define curlssl_connect_nonblocking Curl_polarssl_connect_nonblocking
#define curlssl_session_free(x)  Curl_polarssl_session_free(x)
#define curlssl_close_all Curl_polarssl_close_all
#define curlssl_close Curl_polarssl_close
#define curlssl_shutdown(x,y) 0
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) (x=x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_version Curl_polarssl_version
#define curlssl_check_cxn(x) (x=x, -1)
#define curlssl_data_pending(x,y) (x=x, y=y, 0)

#endif /* USE_POLARSSL */
#endif /* HEADER_CURL_POLARSSL_H */
