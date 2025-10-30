#ifndef HEADER_CURL_HTTP_AWS_SIGV4A_H
#define HEADER_CURL_HTTP_AWS_SIGV4A_H
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

#ifndef CURL_DISABLE_AWS

/* SigV4A support will be determined at compile time in the .c files */
#ifndef HAVE_SIGV4A_SUPPORT
#define HAVE_SIGV4A_SUPPORT 0
#endif

/*
 * Derive SigV4A signing key from AWS credentials
 * Returns CURLE_OK on success, error code on failure
 */
CURLcode Curl_aws_sigv4a_derive_key(const char *access_key,
                                     const char *secret_key,
                                     unsigned char *private_key);

/*
 * Sign string using SigV4A ECDSA algorithm
 * Returns CURLE_OK on success, error code on failure
 */
CURLcode Curl_aws_sigv4a_sign(const unsigned char *private_key,
                               const char *string_to_sign,
                               size_t string_len,
                               unsigned char *signature,
                               size_t *signature_len);

#endif /* !CURL_DISABLE_AWS */

#endif /* HEADER_CURL_HTTP_AWS_SIGV4A_H */
