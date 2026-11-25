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

#include "curl_sha256.h"
#ifdef CURL_HAVE_SHA256

#ifdef USE_OPENSSL_SHA256
#include <openssl/evp.h>

typedef EVP_MD_CTX *my_sha256_ctx;

static CURLcode my_sha256_init(void *pctx)
{
  EVP_MD_CTX ** const ctx = pctx;

  *ctx = EVP_MD_CTX_new();
  if(!*ctx)
    return CURLE_OUT_OF_MEMORY;

  if(!EVP_DigestInit_ex(*ctx, EVP_sha256(), NULL)) {
    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static CURLcode my_sha256_update(void *pctx,
                                 const void *input, size_t input_len)
{
  EVP_MD_CTX ** const ctx = pctx;
  return EVP_DigestUpdate(*ctx, input, input_len) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
}

static CURLcode my_sha256_final(uint8_t *digest, void *pctx)
{
  EVP_MD_CTX ** const ctx = pctx;
  CURLcode result = EVP_DigestFinal_ex(*ctx, digest, NULL) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;
  return result;
}

#elif defined(USE_WOLFSSL_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

typedef struct wc_Sha256 my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
  if(wc_InitSha256(ctx))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode my_sha256_update(void *ctx,
                                 const void *input, size_t input_len)
{
  const byte *bytes = input;
  do {
    word32 ilen = (word32)CURLMIN(input_len, UINT32_MAX);
    if(wc_Sha256Update(ctx, bytes, ilen))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    input_len -= ilen;
    bytes += ilen;
  } while(input_len);
  return CURLE_OK;
}

static CURLcode my_sha256_final(uint8_t *digest, void *ctx)
{
  if(wc_Sha256Final(ctx, digest))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#elif defined(USE_GNUTLS_SHA256)
#include <nettle/sha2.h>
#include <nettle/version.h>

typedef struct sha256_ctx my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
  sha256_init(ctx);
  return CURLE_OK;
}

static CURLcode my_sha256_update(void *ctx,
                                 const void *input, size_t input_len)
{
  sha256_update(ctx, input_len, input);
  return CURLE_OK;
}

static CURLcode my_sha256_final(uint8_t *digest, void *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  sha256_digest(ctx, digest);
#else
  sha256_digest(ctx, SHA256_DIGEST_SIZE, digest);
#endif
  return CURLE_OK;
}

#elif defined(USE_MBEDTLS_SHA256)
#include <psa/crypto.h>

typedef psa_hash_operation_t my_sha256_ctx;

static CURLcode my_sha256_init(void *pctx)
{
  psa_hash_operation_t *ctx = pctx;
  *ctx = psa_hash_operation_init();
  if(psa_hash_setup(ctx, PSA_ALG_SHA_256) != PSA_SUCCESS)
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode my_sha256_update(void *ctx,
                                 const void *input, size_t input_len)
{
  if(psa_hash_update(ctx, input, input_len) != PSA_SUCCESS)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

static CURLcode my_sha256_final(uint8_t *digest, void *ctx)
{
  size_t actual_length;
  if(psa_hash_finish(ctx, digest, CURL_SHA256_DIGEST_LENGTH,
                     &actual_length) != PSA_SUCCESS)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#elif defined(USE_APPLE_SHA256)
#include <CommonCrypto/CommonDigest.h>

typedef CC_SHA256_CTX my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
  (void)CC_SHA256_Init(ctx);  /* always returns 1 */
  return CURLE_OK;
}

static CURLcode my_sha256_update(void *ctx,
                                 const void *input, size_t input_len)
{
  const uint8_t *bytes = input;
  do {
    CC_LONG ilen = (CC_LONG)CURLMIN(input_len, UINT32_MAX);
    CC_SHA256_Update(ctx, bytes, ilen);  /* always returns 1 */
    input_len -= ilen;
    bytes += ilen;
  } while(input_len);
  return CURLE_OK;
}

static CURLcode my_sha256_final(uint8_t *digest, void *ctx)
{
  (void)CC_SHA256_Final(digest, ctx);  /* always returns 1 */
  return CURLE_OK;
}

#elif defined(USE_WIN32_SHA256)
#include <bcrypt.h>

struct sha256_ctx {
  BCRYPT_ALG_HANDLE hAlg;
  BCRYPT_HASH_HANDLE hHash;
};
typedef struct sha256_ctx my_sha256_ctx;

static CURLcode my_sha256_init(void *pctx)
{
  struct sha256_ctx *ctx = pctx;

  ctx->hAlg = ctx->hHash = NULL;
  if(!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&ctx->hAlg,
                                                 BCRYPT_SHA256_ALGORITHM,
                                                 NULL, 0)))
    return CURLE_FAILED_INIT;
  if(!BCRYPT_SUCCESS(BCryptCreateHash(ctx->hAlg, &ctx->hHash,
                                      NULL, 0, NULL, 0, 0))) {
    BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    ctx->hAlg = NULL;
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static CURLcode my_sha256_update(void *pctx,
                                 const void *input, size_t input_len)
{
  struct sha256_ctx *ctx = pctx;
  const BYTE *bytes = input;
  do {
    ULONG ilen = (ULONG)CURLMIN(input_len, ULONG_MAX);
    if(!BCRYPT_SUCCESS(BCryptHashData(ctx->hHash, CURL_UNCONST(bytes),
                                      ilen, 0)))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    input_len -= ilen;
    bytes += ilen;
  } while(input_len);
  return CURLE_OK;
}

static CURLcode my_sha256_final(uint8_t *digest, void *pctx)
{
  struct sha256_ctx *ctx = pctx;
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  if(BCRYPT_SUCCESS(BCryptFinishHash(ctx->hHash,
                                     digest, CURL_SHA256_DIGEST_LENGTH, 0)))
    result = CURLE_OK;
  BCryptDestroyHash(ctx->hHash);
  ctx->hHash = NULL;
  if(ctx->hAlg) {
    BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    ctx->hAlg = NULL;
  }
  return result;
}

#endif /* CRYPTO LIBS */

const struct HMAC_params Curl_HMAC_SHA256 = {
  my_sha256_init,           /* Hash initialization function. */
  my_sha256_update,         /* Hash update function. */
  my_sha256_final,          /* Hash computation end function. */
  sizeof(my_sha256_ctx),    /* Size of hash context structure. */
  64,                       /* Maximum key length. */
  CURL_SHA256_DIGEST_LENGTH /* Result size. */
};

/*
 * Curl_sha256it()
 *
 * Generates a SHA256 hash for the given input data.
 *
 * Parameters:
 *
 * digest [in/out] - The output buffer.
 * input [in]      - The input data.
 * input_len [in]  - The input length.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sha256it(uint8_t *digest, const void *input, size_t input_len)
{
  my_sha256_ctx ctx;
  CURLcode result = my_sha256_init(&ctx);
  if(result)
    return result;

  result = my_sha256_update(&ctx, input, input_len);
  if(result) {
    (void)my_sha256_final(digest, &ctx);
    return result;
  }

  return my_sha256_final(digest, &ctx);
}

#else

const struct HMAC_params Curl_HMAC_SHA256 = {
  NULL,                     /* Hash initialization function. */
  NULL,                     /* Hash update function. */
  NULL,                     /* Hash computation end function. */
  0,                        /* Size of hash context structure. */
  64,                       /* Maximum key length. */
  CURL_SHA256_DIGEST_LENGTH /* Result size. */
};

CURLcode Curl_sha256it(uint8_t *digest, const void *input, size_t input_len)
{
  (void)digest;
  (void)input;
  (void)input_len;
  return CURLE_NOT_BUILT_IN;
}

#endif /* CURL_HAVE_SHA256 */

#endif /* AWS, httpsig, DIGEST, or libssh2 */
