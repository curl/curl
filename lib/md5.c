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

#include "curl_md5.h"

#ifdef CURL_HAVE_MD5

#ifdef USE_OPENSSL_MD5
#include <openssl/evp.h>

typedef EVP_MD_CTX *my_md5_ctx;

static CURLcode my_md5_init(void *pctx)
{
  EVP_MD_CTX ** const ctx = pctx;

  *ctx = EVP_MD_CTX_new();
  if(!*ctx)
    return CURLE_OUT_OF_MEMORY;

  if(!EVP_DigestInit_ex(*ctx, EVP_md5(), NULL)) {
    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static CURLcode my_md5_update(void *pctx, const void *input, size_t input_len)
{
  EVP_MD_CTX ** const ctx = pctx;
  return EVP_DigestUpdate(*ctx, input, input_len) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
}

static CURLcode my_md5_final(uint8_t *digest, void *pctx)
{
  EVP_MD_CTX ** const ctx = pctx;
  CURLcode result = EVP_DigestFinal_ex(*ctx, digest, NULL) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;
  return result;
}

#elif defined(USE_WOLFSSL_MD5)
#include <wolfssl/wolfcrypt/md5.h>

typedef wc_Md5 my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  if(wc_InitMd5(ctx))
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static CURLcode my_md5_update(void *ctx, const void *input, size_t input_len)
{
  const byte *bytes = input;
  do {
    word32 ilen = (word32)CURLMIN(input_len, UINT32_MAX);
    if(wc_Md5Update(ctx, bytes, ilen))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    input_len -= ilen;
    bytes += ilen;
  } while(input_len);
  return CURLE_OK;
}

static CURLcode my_md5_final(uint8_t *digest, void *ctx)
{
  if(wc_Md5Final(ctx, digest))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#elif defined(USE_GNUTLS_MD5)
#include <nettle/md5.h>
#include <nettle/version.h>

typedef struct md5_ctx my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  md5_init(ctx);
  return CURLE_OK;
}

static CURLcode my_md5_update(void *ctx, const void *input, size_t input_len)
{
  md5_update(ctx, input_len, input);
  return CURLE_OK;
}

static CURLcode my_md5_final(uint8_t *digest, void *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  md5_digest(ctx, digest);
#else
  md5_digest(ctx, CURL_MD5_DIGEST_LEN, digest);
#endif
  return CURLE_OK;
}

#elif defined(USE_MBEDTLS_MD5)
#include <psa/crypto.h>

typedef psa_hash_operation_t my_md5_ctx;

static CURLcode my_md5_init(void *pctx)
{
  psa_hash_operation_t *ctx = pctx;
  *ctx = psa_hash_operation_init();
  if(psa_hash_setup(pctx, PSA_ALG_MD5) != PSA_SUCCESS)
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode my_md5_update(void *ctx, const void *input, size_t input_len)
{
  if(psa_hash_update(ctx, input, input_len) != PSA_SUCCESS)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

static CURLcode my_md5_final(uint8_t *digest, void *ctx)
{
  size_t actual_length;
  if(psa_hash_finish(ctx, digest, CURL_MD5_DIGEST_LEN,
                     &actual_length) != PSA_SUCCESS)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#elif defined(USE_APPLE_MD5)
#include <CommonCrypto/CommonDigest.h>

/* For Apple operating systems: CommonCrypto has the functions we need.
   These functions are available on Tiger and later, as well as iOS 2.0
   and later. If you are building for an older cat, well, sorry.

   Declaring the functions as static like this seems to be a bit more
   reliable than defining COMMON_DIGEST_FOR_OPENSSL on older cats. */
typedef CC_MD5_CTX my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  (void)CC_MD5_Init(ctx);  /* always returns 1 */
  return CURLE_OK;
}

static CURLcode my_md5_update(void *ctx, const void *input, size_t input_len)
{
  const uint8_t *bytes = input;
  do {
    CC_LONG ilen = (CC_LONG)CURLMIN(input_len, UINT32_MAX);
    CC_MD5_Update(ctx, bytes, ilen);  /* always returns 1 */
    input_len -= ilen;
    bytes += ilen;
  } while(input_len);
  return CURLE_OK;
}

static CURLcode my_md5_final(uint8_t *digest, void *ctx)
{
  CC_MD5_Final(digest, ctx);  /* always returns 1 */
  return CURLE_OK;
}

#elif defined(USE_WIN32_MD5)
#include <bcrypt.h>

struct md5_ctx {
  BCRYPT_ALG_HANDLE hAlg;
  BCRYPT_HASH_HANDLE hHash;
};
typedef struct md5_ctx my_md5_ctx;

static CURLcode my_md5_init(void *pctx)
{
  struct md5_ctx *ctx = pctx;

  ctx->hAlg = ctx->hHash = NULL;
  if(!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&ctx->hAlg,
                                                 BCRYPT_MD5_ALGORITHM,
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

static CURLcode my_md5_update(void *pctx, const void *input, size_t input_len)
{
  struct md5_ctx *ctx = pctx;
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

static CURLcode my_md5_final(uint8_t *digest, void *pctx)
{
  struct md5_ctx *ctx = pctx;
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  if(BCRYPT_SUCCESS(BCryptFinishHash(ctx->hHash,
                                     digest, CURL_MD5_DIGEST_LEN, 0)))
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

const struct HMAC_params Curl_HMAC_MD5 = {
  my_md5_init,        /* Hash initialization function. */
  my_md5_update,      /* Hash update function. */
  my_md5_final,       /* Hash computation end function. */
  sizeof(my_md5_ctx), /* Size of hash context structure. */
  64,                 /* Maximum key length. */
  CURL_MD5_DIGEST_LEN /* Result size. */
};

/*
 * @unittest: 1601
 * Returns CURLE_OK on success.
 */
CURLcode Curl_md5it(uint8_t *digest, const void *input, size_t input_len)
{
  my_md5_ctx ctx;
  CURLcode result = my_md5_init(&ctx);
  if(result)
    return result;

  result = my_md5_update(&ctx, input, input_len);
  if(result) {
    (void)my_md5_final(digest, &ctx);
    return result;
  }

  return my_md5_final(digest, &ctx);
}

void *Curl_MD5_init(void)
{
  my_md5_ctx *ctx = curlx_malloc(sizeof(*ctx));  /* Create MD5 context */
  if(!ctx)
    return ctx;

  if(my_md5_init(ctx)) {
    curlx_free(ctx);
    return NULL;
  }

  return ctx;
}

CURLcode Curl_MD5_update(void *ctx, const void *input, size_t input_len)
{
  return my_md5_update(ctx, input, input_len);
}

CURLcode Curl_MD5_final(void *ctx, uint8_t *digest)
{
  CURLcode result = my_md5_final(digest, ctx);
  curlx_free(ctx);
  return result;
}

#endif /* CURL_HAVE_MD5 */

#endif /* !CURL_DISABLE_DIGEST_AUTH */
