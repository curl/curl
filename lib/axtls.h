#ifndef __AXTLS_H
#define __AXTLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, DirecTV
 * contact: Eric Hu <ehu@directv.com>
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

#ifdef USE_AXTLS
#include "curl/curl.h"
#include "urldata.h"

int Curl_axtls_init(void);
int Curl_axtls_cleanup(void);
CURLcode Curl_axtls_connect(struct connectdata *conn, int sockindex);

/* tell axTLS to close down all open information regarding connections (and
   thus session ID caching etc) */
void Curl_axtls_close_all(struct SessionHandle *data);

 /* close a SSL connection */
void Curl_axtls_close(struct connectdata *conn, int sockindex);

void Curl_axtls_session_free(void *ptr);
size_t Curl_axtls_version(char *buffer, size_t size);
int Curl_axtls_shutdown(struct connectdata *conn, int sockindex);
int Curl_axtls_check_cxn(struct connectdata *conn);

/* API setup for axTLS */
#define curlssl_init Curl_axtls_init
#define curlssl_cleanup Curl_axtls_cleanup
#define curlssl_connect Curl_axtls_connect
#define curlssl_session_free(x)  Curl_axtls_session_free(x)
#define curlssl_close_all Curl_axtls_close_all
#define curlssl_close Curl_axtls_close
#define curlssl_shutdown(x,y) Curl_axtls_shutdown(x,y)
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_FAILED_INIT)
#define curlssl_set_engine_default(x) (x=x, CURLE_FAILED_INIT)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_version Curl_axtls_version
#define curlssl_check_cxn(x) Curl_axtls_check_cxn(x)
#define curlssl_data_pending(x,y) (x=x, y=y, 0)

#endif /* USE_AXTLS */
#endif
