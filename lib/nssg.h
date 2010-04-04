#ifndef __NSSG_H
#define __NSSG_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef USE_NSS
/*
 * This header should only be needed to get included by sslgen.c and nss.c
 */

#include "urldata.h"
CURLcode Curl_nss_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_nss_connect_nonblocking(struct connectdata *conn,
                                      int sockindex,
                                      bool *done);
/* close a SSL connection */
void Curl_nss_close(struct connectdata *conn, int sockindex);

/* tell NSS to close down all open information regarding connections (and
   thus session ID caching etc) */
int Curl_nss_close_all(struct SessionHandle *data);

int Curl_nss_init(void);
void Curl_nss_cleanup(void);

/* for documentation see Curl_ssl_send() in sslgen.h */
int Curl_nss_send(struct connectdata *conn,
                  int sockindex,
                  const void *mem,
                  size_t len,
                  int *curlcode);

/* for documentation see Curl_ssl_recv() in sslgen.h */
ssize_t Curl_nss_recv(struct connectdata *conn, /* connection data */
                      int num,                  /* socketindex */
                      char *buf,                /* store read data here */
                      size_t buffersize,        /* max amount to read */
                      int *curlcode);

size_t Curl_nss_version(char *buffer, size_t size);
int Curl_nss_check_cxn(struct connectdata *cxn);
int Curl_nss_seed(struct SessionHandle *data);

/* API setup for NSS */
#define curlssl_init Curl_nss_init
#define curlssl_cleanup Curl_nss_cleanup
#define curlssl_connect Curl_nss_connect

/* NSS has its own session ID cache */
#define curlssl_session_free(x)
#define curlssl_close_all Curl_nss_close_all
#define curlssl_close Curl_nss_close
/* NSS has no shutdown function provided and thus always fail */
#define curlssl_shutdown(x,y) (x=x, y=y, 1)
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_FAILED_INIT)
#define curlssl_set_engine_default(x) (x=x, CURLE_FAILED_INIT)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_send Curl_nss_send
#define curlssl_recv Curl_nss_recv
#define curlssl_version Curl_nss_version
#define curlssl_check_cxn(x) Curl_nss_check_cxn(x)
#define curlssl_data_pending(x,y) (x=x, y=y, 0)

#endif /* USE_NSS */
#endif
