#ifndef HEADER_FETCH_HTTP_DIGEST_H
#define HEADER_FETCH_HTTP_DIGEST_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetch_setup.h"

#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_DIGEST_AUTH)

/* this is for digest header input */
FETCHcode Curl_input_digest(struct Curl_easy *data,
                            bool proxy, const char *header);

/* this is for creating digest header output */
FETCHcode Curl_output_digest(struct Curl_easy *data,
                             bool proxy,
                             const unsigned char *request,
                             const unsigned char *uripath);

void Curl_http_auth_cleanup_digest(struct Curl_easy *data);

#endif /* !FETCH_DISABLE_HTTP && !FETCH_DISABLE_DIGEST_AUTH */

#endif /* HEADER_FETCH_HTTP_DIGEST_H */
