#ifndef HEADER_CURL_MD5_H
#define HEADER_CURL_MD5_H
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

#ifndef CURL_DISABLE_DIGEST_AUTH

/* Recommended order of crypto backends:
   1. USE_OPENSSL
   2. USE_WOLFSSL
   3. USE_GNUTLS
   4. USE_MBEDTLS
   5. USE_RUSTLS (TBD)
   6. __APPLE__
   7. USE_WIN32_CRYPTO
 */

#ifdef USE_OPENSSL
#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_MD5
#define USE_OPENSSL_MD5
#define CURL_HAVE_MD5
#endif
#endif

#if !defined(CURL_HAVE_MD5) && defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#ifndef NO_MD5
#define USE_WOLFSSL_MD5
#define CURL_HAVE_MD5
#endif
#endif

#if !defined(CURL_HAVE_MD5) && defined(USE_GNUTLS)
#define USE_GNUTLS_MD5
#define CURL_HAVE_MD5
#endif

#if !defined(CURL_HAVE_MD5) && defined(USE_MBEDTLS)
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER < 0x03020000
#error "mbedTLS 3.2.0 or greater required"
#endif
#include <psa/crypto_config.h>
#if defined(PSA_WANT_ALG_MD5) && PSA_WANT_ALG_MD5
#define USE_MBEDTLS_MD5
#define CURL_HAVE_MD5
#endif
#endif

#if !defined(CURL_HAVE_MD5) && \
  (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
           __MAC_OS_X_VERSION_MAX_ALLOWED >= 1040 && \
   defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
           __MAC_OS_X_VERSION_MIN_REQUIRED < 101500) || \
  (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
           __IPHONE_OS_VERSION_MAX_ALLOWED >= 20000 && \
   defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && \
           __IPHONE_OS_VERSION_MIN_REQUIRED < 130000)
#define USE_APPLE_MD5
#define CURL_HAVE_MD5
#endif

#if !defined(CURL_HAVE_MD5) && defined(USE_WIN32_CRYPTO)
#define USE_WIN32_MD5
#define CURL_HAVE_MD5
#endif

#undef CURL_HAVE_MD5

#ifdef CURL_HAVE_MD5
#include "curl_hmac.h"

#define MD5_DIGEST_LEN  16
#define HMAC_MD5_LENGTH 16

typedef CURLcode (*Curl_MD5_init_func)(void *context);
typedef void (*Curl_MD5_update_func)(void *context,
                                     const unsigned char *data,
                                     unsigned int len);
typedef void (*Curl_MD5_final_func)(unsigned char *result, void *context);

struct MD5_params {
  Curl_MD5_init_func md5_init_func;     /* Initialize context procedure */
  Curl_MD5_update_func md5_update_func; /* Update context with data */
  Curl_MD5_final_func md5_final_func;   /* Get final result procedure */
  unsigned int md5_ctxtsize;            /* Context structure size */
  unsigned int md5_resultlen;           /* Result length (bytes) */
};

struct MD5_context {
  const struct MD5_params *md5_hash;  /* Hash function definition */
  void *md5_hashctx;                  /* Hash function context */
};

extern const struct MD5_params Curl_DIGEST_MD5;
extern const struct HMAC_params Curl_HMAC_MD5;

CURLcode Curl_md5it(unsigned char *output, const unsigned char *input,
                    size_t len);

struct MD5_context *Curl_MD5_init(const struct MD5_params *md5params);
CURLcode Curl_MD5_update(struct MD5_context *context,
                         const unsigned char *input,
                         unsigned int len);
CURLcode Curl_MD5_final(struct MD5_context *context, unsigned char *result);
#endif /* CURL_HAVE_MD5 */

#endif /* CURL_DISABLE_DIGEST_AUTH */

#endif /* HEADER_CURL_MD5_H */
