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

/* Please keep the SSL backend-specific #if branches in this order:
 *
 * 1. USE_OPENSSL
 * 2. USE_WOLFSSL
 * 3. USE_GNUTLS
 * 4. USE_MBEDTLS
 */

#include "httpsig_crypto.h"
#include "curl_sha256.h"
#include "curl_hmac.h"

#ifdef USE_OPENSSL
#include <openssl/evp.h>

CURLcode Curl_httpsig_ed25519_sign(const unsigned char *key, size_t keylen,
                                   const unsigned char *msg, size_t msglen,
                                   unsigned char *sig, size_t *siglen)
{
  EVP_PKEY *pkey;
  EVP_MD_CTX *mdctx;
  size_t slen;
  int rc;

  if(keylen != 32)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key, keylen);
  if(!pkey)
    return CURLE_AUTH_ERROR;

  mdctx = EVP_MD_CTX_new();
  if(!mdctx) {
    EVP_PKEY_free(pkey);
    return CURLE_OUT_OF_MEMORY;
  }

  rc = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
  if(rc != 1) {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return CURLE_AUTH_ERROR;
  }

  slen = CURL_HTTPSIG_ED25519_SIGLEN;
  rc = EVP_DigestSign(mdctx, sig, &slen, msg, msglen);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);

  if(rc != 1)
    return CURLE_AUTH_ERROR;

  *siglen = slen;
  return CURLE_OK;
}

#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

CURLcode Curl_httpsig_ed25519_sign(const unsigned char *key, size_t keylen,
                                   const unsigned char *msg, size_t msglen,
                                   unsigned char *sig, size_t *siglen)
{
  int ret;
  WC_RNG rng;
  ed25519_key edkey;
  word32 outlen;
  unsigned char pubkey[ED25519_PUB_KEY_SIZE];

  if(keylen != ED25519_KEY_SIZE)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  ret = wc_InitRng(&rng);
  if(ret)
    return CURLE_AUTH_ERROR;

  ret = wc_ed25519_init(&edkey);
  if(ret) {
    wc_FreeRng(&rng);
    return CURLE_AUTH_ERROR;
  }

  ret = wc_ed25519_import_private_only(key, ED25519_KEY_SIZE, &edkey);
  if(ret)
    goto fail;

  ret = wc_ed25519_make_public(&edkey, pubkey, ED25519_PUB_KEY_SIZE);
  if(ret)
    goto fail;

  ret = wc_ed25519_import_private_key(key, ED25519_KEY_SIZE,
                                      pubkey, ED25519_PUB_KEY_SIZE, &edkey);
  if(ret)
    goto fail;

  outlen = ED25519_SIG_SIZE;
  ret = wc_ed25519_sign_msg(msg, (word32)msglen, sig, &outlen, &edkey);
  if(ret)
    goto fail;

  *siglen = (size_t)outlen;
  wc_ed25519_free(&edkey);
  wc_FreeRng(&rng);
  return CURLE_OK;

fail:
  wc_ed25519_free(&edkey);
  wc_FreeRng(&rng);
  return CURLE_AUTH_ERROR;
}

#else /* no Ed25519-capable backend */

CURLcode Curl_httpsig_ed25519_sign(const unsigned char *key, size_t keylen,
                                   const unsigned char *msg, size_t msglen,
                                   unsigned char *sig, size_t *siglen)
{
  (void)key; (void)keylen; (void)msg; (void)msglen;
  (void)sig; (void)siglen;
  return CURLE_NOT_BUILT_IN;
}

#endif /* Ed25519 backends */

CURLcode Curl_httpsig_hmac_sha256_sign(const unsigned char *key, size_t keylen,
                                       const unsigned char *msg, size_t msglen,
                                       unsigned char *sig, size_t *siglen)
{
  CURLcode result;
  result = Curl_hmacit(&Curl_HMAC_SHA256, key, keylen, msg, msglen, sig);
  if(!result)
    *siglen = CURL_HTTPSIG_HMAC_SHA256_SIGLEN;
  return result;
}

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_HTTPSIG */
