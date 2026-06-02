#ifndef HEADER_CURL_H3_PROXY_H
#define HEADER_CURL_H3_PROXY_H
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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_PROXY) && \
  defined(USE_PROXY_HTTP3) && defined(USE_NGHTTP3) &&              \
  defined(USE_NGTCP2) && defined(USE_OPENSSL)

CURLcode Curl_cf_ngtcp2_proxy_insert_after(struct Curl_cfilter *cf_at,
                                           struct Curl_easy *data,
                                           struct Curl_peer *dest,
                                           bool udp_tunnel);

CURLcode Curl_cf_ngtcp2_proxy_create(struct Curl_cfilter **pcf,
                                     struct Curl_easy *data,
                                     struct connectdata *conn,
                                     struct Curl_sockaddr_ex *addr,
                                     uint8_t transport_in,
                                     uint8_t transport_out);

#endif

#endif /* HEADER_CURL_H3_PROXY_H */
