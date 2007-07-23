#ifndef __QSSL_H
#define __QSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

/*
 * This header should only be needed to get included by sslgen.c and qssl.c
 */

#include "urldata.h"

int Curl_qsossl_init(void);
void Curl_qsossl_cleanup(void);
CURLcode Curl_qsossl_connect(struct connectdata * conn, int sockindex);
void Curl_qsossl_close(struct connectdata * conn); /* close a SSL connection */
int Curl_qsossl_close_all(struct SessionHandle * data);
int Curl_qsossl_shutdown(struct connectdata * conn, int sockindex);

ssize_t Curl_qsossl_send(struct connectdata * conn,
                         int sockindex,
                         void * mem,
                         size_t len);
ssize_t Curl_qsossl_recv(struct connectdata * conn, /* connection data */
                         int num,                   /* socketindex */
                         char * buf,                /* store read data here */
                         size_t buffersize,         /* max amount to read */
                         bool * wouldblock);

size_t Curl_qsossl_version(char * buffer, size_t size);
int Curl_qsossl_check_cxn(struct connectdata * cxn);

#endif
