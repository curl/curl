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

static CURLcode my_md5_init(void *in)
{
  EVP_MD_CTX ** const ctx = in;

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

static void my_md5_update(void *in, const void *input, size_t len)
{
  EVP_MD_CTX ** const ctx = in;
  (void)EVP_DigestUpdate(*ctx, input, len);
}

static void my_md5_final(unsigned char *digest, void *in)
{
  EVP_MD_CTX ** const ctx = in;
  (void)EVP_DigestFinal_ex(*ctx, digest, NULL);
  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;
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

static void my_md5_update(void *ctx, const void *input, size_t len)
{
  const byte *bytes = input;
  do {
    word32 ilen = (word32)CURLMIN(len, UINT32_MAX);
    (void)wc_Md5Update(ctx, bytes, ilen);
    len -= ilen;
    bytes += ilen;
  } while(len);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
  (void)wc_Md5Final(ctx, digest);
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

static void my_md5_update(void *ctx, const void *input, size_t len)
{
  md5_update(ctx, len, input);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  md5_digest(ctx, digest);
#else
  md5_digest(ctx, CURL_MD5_DIGEST_LEN, digest);
#endif
}

#elif defined(USE_MBEDTLS_MD5)
#include <psa/crypto.h>

typedef psa_hash_operation_t my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  psa_hash_operation_t *pctx = ctx;
  *pctx = psa_hash_operation_init();
  if(psa_hash_setup(pctx, PSA_ALG_MD5) != PSA_SUCCESS)
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static void my_md5_update(void *ctx, const void *input, size_t len)
{
  (void)psa_hash_update(ctx, input, len);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
  size_t actual_length;
  (void)psa_hash_finish(ctx, digest, CURL_MD5_DIGEST_LEN, &actual_length);
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

static void my_md5_update(void *ctx, const void *input, size_t len)
{
  const uint8_t *bytes = input;
  do {
    CC_LONG ilen = (CC_LONG)CURLMIN(len, UINT32_MAX);
    CC_MD5_Update(ctx, bytes, ilen);
    len -= ilen;
    bytes += ilen;
  } while(len);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
  CC_MD5_Final(digest, ctx);
}

#elif defined(USE_WIN32_MD5)
#include <wincrypt.h>

struct md5_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct md5_ctx my_md5_ctx;

static CURLcode my_md5_init(void *in)
{
  struct md5_ctx *ctx = in;
  if(!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return CURLE_OUT_OF_MEMORY;

  if(!CryptCreateHash(ctx->hCryptProv, CALG_MD5, 0, 0, &ctx->hHash)) {
    CryptReleaseContext(ctx->hCryptProv, 0);
    ctx->hCryptProv = 0;
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static void my_md5_update(void *in, const void *input, size_t len)
{
  struct md5_ctx *ctx = in;
  const BYTE *bytes = input;
  do {
    DWORD ilen = (DWORD)CURLMIN(len, 0xffffffffUL);
    CryptHashData(ctx->hHash, bytes, ilen, 0);
    len -= ilen;
    bytes += ilen;
  } while(len);
}

static void my_md5_final(unsigned char *digest, void *in)
{
  struct md5_ctx *ctx = in;
  DWORD length = 0;
  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == CURL_MD5_DIGEST_LEN)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);
  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);
  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
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
CURLcode Curl_md5it(uint8_t *output, const void *input, size_t len)
{
  CURLcode result;
  my_md5_ctx ctx;

  result = my_md5_init(&ctx);
  if(!result) {
    my_md5_update(&ctx, input, len);
    my_md5_final(output, &ctx);
  }
  return result;
}

void *Curl_MD5_init(void)
{
  my_md5_ctx *ctxt = curlx_malloc(sizeof(*ctxt));  /* Create MD5 context */
  if(!ctxt)
    return ctxt;

  if(my_md5_init(ctxt)) {
    curlx_free(ctxt);
    return NULL;
  }

  return ctxt;
}

CURLcode Curl_MD5_update(void *context, const void *input, size_t len)
{
  my_md5_update(context, input, len);
  return CURLE_OK;
}

CURLcode Curl_MD5_final(void *context, uint8_t *result)
{
  my_md5_final(result, context);
  curlx_free(context);
  return CURLE_OK;
}

#endif /* CURL_HAVE_MD5 */

#endif /* !CURL_DISABLE_DIGEST_AUTH */
