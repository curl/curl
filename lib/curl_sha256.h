#ifndef HEADER_CURL_SHA256_H
#define HEADER_CURL_SHA256_H
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

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_HTTPSIG) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||                             \
  defined(USE_LIBSSH2) || defined(USE_SSL)

/* Please keep the SSL backend-specific #if branches in this order:

   1. USE_OPENSSL
   2. USE_WOLFSSL
   3. USE_GNUTLS
   4. USE_MBEDTLS
   5. USE_RUSTLS (TBD)
   6. __APPLE__
   7. USE_WIN32_CRYPTO

   This ensures that the same SSL branch gets activated throughout this source
   file even if multiple backends are enabled at the same time.
 */

#ifdef USE_OPENSSL
#define USE_OPENSSL_SHA256
#define CURL_HAVE_SHA256
#endif

#if !defined(CURL_HAVE_SHA256) && defined(USE_WOLFSSL)
#define USE_WOLFSSL_SHA256
#define CURL_HAVE_SHA256
#endif

#if !defined(CURL_HAVE_SHA256) && defined(USE_GNUTLS)
#define USE_GNUTLS_SHA256
#define CURL_HAVE_SHA256
#endif

#if !defined(CURL_HAVE_SHA256) && defined(USE_MBEDTLS)
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER < 0x03020000
#error "mbedTLS 3.2.0 or greater required"
#endif
#include <psa/crypto_config.h>
#if defined(PSA_WANT_ALG_SHA_256) && PSA_WANT_ALG_SHA_256
#define USE_MBEDTLS_SHA256
#define CURL_HAVE_SHA256
#endif
#endif

#if !defined(CURL_HAVE_SHA256) && \
  (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
           __MAC_OS_X_VERSION_MAX_ALLOWED >= 1040) || \
  (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
           __IPHONE_OS_VERSION_MAX_ALLOWED >= 20000)
#define USE_APPLE_SHA256
#define CURL_HAVE_SHA256
#endif

#if !defined(CURL_HAVE_SHA256) && defined(USE_WIN32_CRYPTO)
#define USE_WIN32_SHA256
#define CURL_HAVE_SHA256
#endif

#ifdef CURL_HAVE_SHA256
#include "curl_hmac.h"

extern const struct HMAC_params Curl_HMAC_SHA256;

#ifndef CURL_SHA256_DIGEST_LENGTH
#define CURL_SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

CURLcode Curl_sha256it(unsigned char *output, const unsigned char *input,
                       size_t len);
#endif /* CURL_HAVE_SHA256 */

#endif /* AWS, httpsig, DIGEST, or libssh2 */

#endif /* HEADER_CURL_SHA256_H */
