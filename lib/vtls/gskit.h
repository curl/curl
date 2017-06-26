#ifndef HEADER_CURL_GSKIT_H
#define HEADER_CURL_GSKIT_H
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

/*
 * This header should only be needed to get included by vtls.c and gskit.c
 */

#include "urldata.h"

#ifdef USE_GSKIT
int Curl_gskit_init(void);
void Curl_gskit_cleanup(void);
CURLcode Curl_gskit_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_gskit_connect_nonblocking(struct connectdata *conn,
                                        int sockindex, bool *done);
void Curl_gskit_close(struct connectdata *conn, int sockindex);
int Curl_gskit_shutdown(struct connectdata *conn, int sockindex);

size_t Curl_gskit_version(char *buffer, size_t size);
int Curl_gskit_check_cxn(struct connectdata *cxn);

extern const struct Curl_ssl Curl_ssl_gskit;

/* Set the API backend definition to GSKit */
#define CURL_SSL_BACKEND CURLSSLBACKEND_GSKIT

#endif /* USE_GSKIT */

#endif /* HEADER_CURL_GSKIT_H */
