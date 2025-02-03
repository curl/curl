#ifndef HEADER_FETCH_SHA512_256_H
#define HEADER_FETCH_SHA512_256_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Evgeny Grin (Karlson2k), <k2k@narod.ru>.
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

#if !defined(FETCH_DISABLE_DIGEST_AUTH) && !defined(FETCH_DISABLE_SHA512_256)

#include <fetch/fetch.h>
#include "fetch_hmac.h"

#define FETCH_HAVE_SHA512_256

extern const struct HMAC_params Fetch_HMAC_SHA512_256[1];

#define FETCH_SHA512_256_DIGEST_LENGTH 32

FETCHcode
Fetch_sha512_256it(unsigned char *output, const unsigned char *input,
                  size_t input_size);

#endif /* !FETCH_DISABLE_DIGEST_AUTH && !FETCH_DISABLE_SHA512_256 */

#endif /* HEADER_FETCH_SHA256_H */
