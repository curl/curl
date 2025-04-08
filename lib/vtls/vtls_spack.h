#ifndef HEADER_CURL_VTLS_SPACK_H
#define HEADER_CURL_VTLS_SPACK_H
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
#include "../curl_setup.h"

#ifdef USE_SSLS_EXPORT

struct dynbuf;
struct Curl_ssl_session;

CURLcode Curl_ssl_session_pack(struct Curl_easy *data,
                               struct Curl_ssl_session *s,
                               struct dynbuf *buf);

CURLcode Curl_ssl_session_unpack(struct Curl_easy *data,
                                 const void *bufv, size_t buflen,
                                 struct Curl_ssl_session **ps);

#endif /* USE_SSLS_EXPORT */

#endif /* HEADER_CURL_VTLS_SPACK_H */
