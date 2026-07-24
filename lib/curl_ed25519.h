#ifndef HEADER_CURL_ED25519_H
#define HEADER_CURL_ED25519_H
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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_HTTPSIG)

#define CURL_ED25519_SIGLEN 64
#define CURL_ED25519_KEYLEN 32

/* Sign with Ed25519 (RFC 8032).
 * key/keylen: raw 32-byte private seed
 * msg/msglen: data to sign
 * sig: output buffer (at least CURL_ED25519_SIGLEN bytes)
 * siglen: out - actual signature length on success
 * Returns CURLE_OK or CURLE_NOT_BUILT_IN if no backend supports Ed25519. */
CURLcode Curl_ed25519_sign(const unsigned char *key, size_t keylen,
                           const unsigned char *msg, size_t msglen,
                           unsigned char *sig, size_t *siglen);

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_HTTPSIG */
#endif /* HEADER_CURL_ED25519_H */
