#ifndef HEADER_CURL_VQUIC_CURL_NGTCP2_H
#define HEADER_CURL_VQUIC_CURL_NGTCP2_H
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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGTCP2) && defined(USE_NGHTTP3)

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

struct Curl_cfilter;

#include "urldata.h"

void Curl_ngtcp2_ver(char *p, size_t len);

CURLcode Curl_cf_ngtcp2_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct Curl_addrinfo *ai);
#endif

#endif /* HEADER_CURL_VQUIC_CURL_NGTCP2_H */
