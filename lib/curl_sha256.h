#ifndef HEADER_FETCH_SHA256_H
#define HEADER_FETCH_SHA256_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Florin Petriuc, <petriuc.florin@gmail.com>
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://fetch.se/docs/copyright.html.
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

#if !defined(FETCH_DISABLE_AWS) || !defined(FETCH_DISABLE_DIGEST_AUTH) \
    || defined(USE_LIBSSH2) || defined(USE_SSL)

#include <fetch/fetch.h>
#include "fetch_hmac.h"

extern const struct HMAC_params Curl_HMAC_SHA256;

#ifndef FETCH_SHA256_DIGEST_LENGTH
#define FETCH_SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

FETCHcode Curl_sha256it(unsigned char *outbuffer, const unsigned char *input,
                       const size_t len);

#endif

#endif /* HEADER_FETCH_SHA256_H */
