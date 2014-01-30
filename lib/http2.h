#ifndef HEADER_CURL_HTTP2_H
#define HEADER_CURL_HTTP2_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef USE_NGHTTP2
#include "http.h"
/*
 * Store nghttp2 version info in this buffer, Prefix with a space.  Return
 * total length written.
 */
int Curl_http2_ver(char *p, size_t len);

CURLcode Curl_http2_init(struct connectdata *conn);
CURLcode Curl_http2_send_request(struct connectdata *conn);
CURLcode Curl_http2_request_upgrade(Curl_send_buffer *req,
                                    struct connectdata *conn);
int Curl_http2_switched(struct connectdata *conn);
#else /* USE_NGHTTP2 */
#define Curl_http2_init(x)
#define Curl_http2_send_request(x)
#define Curl_http2_request_upgrade(x,y) CURLE_OK
#define Curl_http2_switched(x)
#endif

#endif /* HEADER_CURL_HTTP2_H */

