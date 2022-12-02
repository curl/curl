#ifndef HEADER_CURL_HTTP_PROXY_H
#define HEADER_CURL_HTTP_PROXY_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "urldata.h"

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

/* Default proxy timeout in milliseconds */
#define PROXY_TIMEOUT (3600*1000)

CURLcode Curl_conn_http_proxy_add(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex);

CURLcode Curl_conn_haproxy_add(struct Curl_easy *data,
                               struct connectdata *conn,
                               int sockindex);

#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

#endif /* HEADER_CURL_HTTP_PROXY_H */
