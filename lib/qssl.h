#ifndef HEADER_CURL_QSSL_H
#define HEADER_CURL_QSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * This header should only be needed to get included by sslgen.c and qssl.c
 */

#include "urldata.h"

#ifdef USE_QSOSSL
int Curl_qsossl_init(void);
void Curl_qsossl_cleanup(void);
CURLcode Curl_qsossl_connect(struct connectdata * conn, int sockindex);
void Curl_qsossl_close(struct connectdata *conn, int sockindex);
int Curl_qsossl_close_all(struct SessionHandle * data);
int Curl_qsossl_shutdown(struct connectdata * conn, int sockindex);

size_t Curl_qsossl_version(char * buffer, size_t size);
int Curl_qsossl_check_cxn(struct connectdata * cxn);

/* API setup for QsoSSL */
#define curlssl_init Curl_qsossl_init
#define curlssl_cleanup Curl_qsossl_cleanup
#define curlssl_connect Curl_qsossl_connect

/*  No session handling for QsoSSL */
#define curlssl_session_free(x) Curl_nop_stmt
#define curlssl_close_all Curl_qsossl_close_all
#define curlssl_close Curl_qsossl_close
#define curlssl_shutdown(x,y) Curl_qsossl_shutdown(x,y)
#define curlssl_set_engine(x,y) CURLE_NOT_BUILT_IN
#define curlssl_set_engine_default(x) CURLE_NOT_BUILT_IN
#define curlssl_engines_list(x) NULL
#define curlssl_version Curl_qsossl_version
#define curlssl_check_cxn(x) Curl_qsossl_check_cxn(x)
#define curlssl_data_pending(x,y) 0
#endif /* USE_QSOSSL */

#endif /* HEADER_CURL_QSSL_H */
