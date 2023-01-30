#ifndef HEADER_CURL_SENDF_H
#define HEADER_CURL_SENDF_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#include "curl_log.h"


#define CLIENTWRITE_BODY    (1<<0)
#define CLIENTWRITE_HEADER  (1<<1)
#define CLIENTWRITE_STATUS  (1<<2) /* the first "header" is the status line */
#define CLIENTWRITE_CONNECT (1<<3) /* a CONNECT response */
#define CLIENTWRITE_1XX     (1<<4) /* a 1xx response */
#define CLIENTWRITE_TRAILER (1<<5) /* a trailer header */
#define CLIENTWRITE_BOTH   (CLIENTWRITE_BODY|CLIENTWRITE_HEADER)

CURLcode Curl_client_write(struct Curl_easy *data, int type, char *ptr,
                           size_t len) WARN_UNUSED_RESULT;

/* internal read-function, does plain socket, SSL and krb4 */
CURLcode Curl_read(struct Curl_easy *data, curl_socket_t sockfd,
                   char *buf, size_t buffersize,
                   ssize_t *n);

/* internal write-function, does plain socket, SSL, SCP, SFTP and krb4 */
CURLcode Curl_write(struct Curl_easy *data,
                    curl_socket_t sockfd,
                    const void *mem, size_t len,
                    ssize_t *written);

#endif /* HEADER_CURL_SENDF_H */
