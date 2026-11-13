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

struct ossl_sha256_ctx {
  EVP_MD_CTX *openssl_ctx;
};
typedef struct ossl_sha256_ctx my_sha256_ctx;

static CURLcode my_sha256_init(void *in)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  ctx->openssl_ctx = EVP_MD_CTX_new();
  if(!ctx->openssl_ctx)
    return CURLE_OUT_OF_MEMORY;

  if(!EVP_DigestInit_ex(ctx->openssl_ctx, EVP_sha256(), NULL)) {
    EVP_MD_CTX_free(ctx->openssl_ctx);
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static void my_sha256_update(void *in,
                             const unsigned char *data,
                             unsigned int length)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  EVP_DigestUpdate(ctx->openssl_ctx, data, length);
}

static void my_sha256_final(unsigned char *digest, void *in)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  EVP_DigestFinal_ex(ctx->openssl_ctx, digest, NULL);
  EVP_MD_CTX_free(ctx->openssl_ctx);
}

#elif defined(USE_WOLFSSL_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

typedef struct wc_Sha256 my_sha256_ctx;

static CURLcode my_sha256_init(void *in)
{
  if(wc_InitSha256(in))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static void my_sha256_update(void *in,
                             const unsigned char *data,
                             unsigned int length)
{
  (void)wc_Sha256Update(in, data, (word32)length);
}

static void my_sha256_final(unsigned char *digest, void *in)
{
  (void)wc_Sha256Final(in, digest);
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

static void my_sha256_update(void *ctx,
                             const unsigned char *data,
                             unsigned int length)
{
  sha256_update(ctx, length, data);
}

static void my_sha256_final(unsigned char *digest, void *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  sha256_digest(ctx, digest);
#else
  sha256_digest(ctx, SHA256_DIGEST_SIZE, digest);
#endif
}

#elif defined(USE_MBEDTLS_SHA256)
#include <psa/crypto.h>

typedef psa_hash_operation_t my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
  psa_hash_operation_t *pctx = (psa_hash_operation_t *)ctx;
  *pctx = psa_hash_operation_init();
  if(psa_hash_setup(pctx, PSA_ALG_SHA_256) != PSA_SUCCESS)
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static void my_sha256_update(void *ctx,
                             const unsigned char *data,
                             unsigned int length)
{
  (void)psa_hash_update(ctx, data, length);
}

static void my_sha256_final(unsigned char *digest, void *ctx)
{
  size_t actual_length;
  (void)psa_hash_finish(ctx, digest, CURL_SHA256_DIGEST_LENGTH,
                        &actual_length);
}

#elif defined(USE_APPLE_SHA256)
#include <CommonCrypto/CommonDigest.h>

typedef CC_SHA256_CTX my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
  (void)CC_SHA256_Init(ctx);  /* always returns 1 */
  return CURLE_OK;
}

static void my_sha256_update(void *ctx,
                             const unsigned char *data,
                             unsigned int length)
{
  (void)CC_SHA256_Update(ctx, data, length);
}

static void my_sha256_final(unsigned char *digest, void *ctx)
{
  (void)CC_SHA256_Final(digest, ctx);
}

#elif defined(USE_WIN32_SHA256)
#include <wincrypt.h>

struct sha256_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct sha256_ctx my_sha256_ctx;

static CURLcode my_sha256_init(void *in)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  if(!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES,
                          CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return CURLE_OUT_OF_MEMORY;

  if(!CryptCreateHash(ctx->hCryptProv, CALG_SHA_256, 0, 0, &ctx->hHash)) {
    CryptReleaseContext(ctx->hCryptProv, 0);
    ctx->hCryptProv = 0;
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static void my_sha256_update(void *in,
                             const unsigned char *data,
                             unsigned int length)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  CryptHashData(ctx->hHash, (const BYTE *)data, length, 0);
}

static void my_sha256_final(unsigned char *digest, void *in)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  unsigned long length = 0;

  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == CURL_SHA256_DIGEST_LENGTH)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);

  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);

  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
}

#endif

/*
 * Curl_sha256it()
 *
 * Generates a SHA256 hash for the given input data.
 *
 * Parameters:
 *
 * output [in/out] - The output buffer.
 * input  [in]     - The input data.
 * length [in]     - The input length.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sha256it(unsigned char *output, const unsigned char *input,
                       size_t len)
{
  CURLcode result;
  my_sha256_ctx ctx;

  result = my_sha256_init(&ctx);
  if(!result) {
    do {
      unsigned int ilen = (unsigned int)CURLMIN(len, UINT_MAX);
      my_sha256_update(&ctx, input, ilen);
      len -= ilen;
      input += ilen;
    } while(len);
    my_sha256_final(output, &ctx);
  }
  return result;
}

const struct HMAC_params Curl_HMAC_SHA256 = {
  my_sha256_init,        /* Hash initialization function. */
  my_sha256_update,      /* Hash update function. */
  my_sha256_final,       /* Hash computation end function. */
  sizeof(my_sha256_ctx), /* Size of hash context structure. */
  64,                    /* Maximum key length. */
  32                     /* Result size. */
};

#else

CURLcode Curl_sha256it(unsigned char *output, const unsigned char *input,
                       size_t len)
{
  (void)output;
  (void)input;
  (void)len;
  return CURLE_NOT_BUILT_IN;
}

const struct HMAC_params Curl_HMAC_SHA256 = {
  NULL,                  /* Hash initialization function. */
  NULL,                  /* Hash update function. */
  NULL,                  /* Hash computation end function. */
  0,                     /* Size of hash context structure. */
  64,                    /* Maximum key length. */
  32                     /* Result size. */
};

#endif /* CURL_HAVE_SHA256 */

#endif /* AWS, httpsig, DIGEST, or libssh2 */
