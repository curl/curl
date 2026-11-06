#ifndef HEADER_CURL_SHA512_256_H
#define HEADER_CURL_SHA512_256_H
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

#if !defined(CURL_DISABLE_DIGEST_AUTH) && !defined(CURL_DISABLE_SHA512_256)

#include "curl_hmac.h"

/* The recommended order of the TLS backends:
 * 1. USE_OPENSSL
 * 2. USE_WOLFSSL
 * 3. USE_GNUTLS
 * 4. USE_MBEDTLS (TBD)
 * 5. USE_RUSTLS (TBD)
 * 6. USE_WIN32_CRYPTO (TBD)
 * Skip the backend if it does not support the required algorithm */

#ifdef USE_OPENSSL
#  include <openssl/opensslv.h>
#  if !defined(LIBRESSL_VERSION_NUMBER) || \
  (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3080000fL)
#    include <openssl/evp.h>
#    define CURL_HAVE_SHA512_256
#    define USE_OPENSSL_SHA512_256          1
#    define HAS_SHA512_256_IMPLEMENTATION   1
#  endif
#endif

#if !defined(HAS_SHA512_256_IMPLEMENTATION) && defined(USE_WOLFSSL)
#  include <wolfssl/options.h>
#  ifndef WOLFSSL_NOSHA512_256
#    define CURL_HAVE_SHA512_256
#    define USE_WOLFSSL_SHA512_256          1
#    define HAS_SHA512_256_IMPLEMENTATION   1
#  endif
#endif

#if !defined(HAS_SHA512_256_IMPLEMENTATION) && defined(USE_GNUTLS)
#  include <nettle/sha2.h>
#  include <nettle/version.h>
#  ifdef SHA512_256_DIGEST_SIZE
#    define CURL_HAVE_SHA512_256
#    define USE_GNUTLS_SHA512_256           1
#  endif
#endif /* !HAS_SHA512_256_IMPLEMENTATION && USE_GNUTLS */

#ifdef CURL_HAVE_SHA512_256
extern const struct HMAC_params Curl_HMAC_SHA512_256[1];

#define CURL_SHA512_256_DIGEST_LENGTH 32

CURLcode Curl_sha512_256it(unsigned char *output, const unsigned char *input,
                           size_t input_size);
#endif /* CURL_HAVE_SHA512_256 */

#endif /* !CURL_DISABLE_DIGEST_AUTH && !CURL_DISABLE_SHA512_256 */

#endif /* HEADER_CURL_SHA256_H */
