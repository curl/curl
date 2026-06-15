#ifndef HEADER_CURL_CF_CAPSULE_H
#define HEADER_CURL_CF_CAPSULE_H
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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

/* Insert a capsule protocol filter after `cf_at` in the filter chain.
 * The capsule filter encapsulates/decapsulates UDP datagrams using
 * the HTTP Datagram capsule format (RFC 9297). */
CURLcode Curl_cf_capsule_insert_after(struct Curl_cfilter *cf_at,
                                      struct Curl_easy *data);

extern struct Curl_cftype Curl_cft_capsule;

#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

#endif /* HEADER_CURL_CF_CAPSULE_H */
