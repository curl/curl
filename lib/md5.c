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

#if (defined(USE_CURL_NTLM_CORE) && !defined(USE_WINDOWS_SSPI)) || \
  !defined(CURL_DISABLE_DIGEST_AUTH)

#include "curl_md5.h"
#include "curl_hmac.h"

#ifdef USE_OPENSSL
#include <openssl/opensslconf.h>
#endif

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#endif

#ifdef USE_MBEDTLS
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER < 0x03020000
#error "mbedTLS 3.2.0 or greater required"
#endif
#include <psa/crypto_config.h>
#endif

#ifdef USE_GNUTLS
#include <nettle/md5.h>
#include <nettle/version.h>

typedef struct md5_ctx my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  md5_init(ctx);
  return CURLE_OK;
}

static void my_md5_update(void *ctx,
                          const unsigned char *input, unsigned int len)
{
  md5_update(ctx, len, input);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  md5_digest(ctx, digest);
#else
  md5_digest(ctx, MD5_DIGEST_LEN, digest);
#endif
}

#elif defined(USE_OPENSSL) && !defined(OPENSSL_NO_MD5)
#include <openssl/evp.h>

typedef EVP_MD_CTX *my_md5_ctx;

static CURLcode my_md5_init(void *in)
{
  EVP_MD_CTX **ctx = (EVP_MD_CTX **)in;
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

static void my_md5_update(void *in,
                          const unsigned char *input, unsigned int len)
{
  EVP_MD_CTX **ctx = (EVP_MD_CTX **)in;
  (void)EVP_DigestUpdate(*ctx, input, len);
}

static void my_md5_final(unsigned char *digest, void *in)
{
  EVP_MD_CTX **ctx = (EVP_MD_CTX **)in;
  (void)EVP_DigestFinal_ex(*ctx, digest, NULL);
  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;
}

#elif defined(USE_WOLFSSL) && !defined(NO_MD5)
#include <wolfssl/wolfcrypt/md5.h>

typedef wc_Md5 my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  if(wc_InitMd5(ctx))
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static void my_md5_update(void *ctx,
                          const unsigned char *input, unsigned int len)
{
  (void)wc_Md5Update(ctx, input, (word32)len);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
  (void)wc_Md5Final(ctx, digest);
}

#elif defined(USE_MBEDTLS) && \
  defined(PSA_WANT_ALG_MD5) && PSA_WANT_ALG_MD5
#include <psa/crypto.h>

typedef psa_hash_operation_t my_md5_ctx;

static CURLcode my_md5_init(void *ctx)
{
  psa_hash_operation_t *pctx = (psa_hash_operation_t *)ctx;
  *pctx = psa_hash_operation_init();
  if(psa_hash_setup(pctx, PSA_ALG_MD5) != PSA_SUCCESS)
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static void my_md5_update(void *ctx,
                          const unsigned char *input, unsigned int len)
{
  (void)psa_hash_update(ctx, input, len);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
  size_t actual_length;
  (void)psa_hash_finish(ctx, digest, MD5_DIGEST_LEN, &actual_length);
}

#elif (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
               __MAC_OS_X_VERSION_MAX_ALLOWED >= 1040 && \
       defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
               __MAC_OS_X_VERSION_MIN_REQUIRED < 101500) || \
      (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
               __IPHONE_OS_VERSION_MAX_ALLOWED >= 20000 && \
       defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && \
               __IPHONE_OS_VERSION_MIN_REQUIRED < 130000)
#include <CommonCrypto/CommonDigest.h>

/* For Apple operating systems: CommonCrypto has the functions we need.
   These functions are available on Tiger and later, as well as iOS 2.0
   and later. If you are building for an older cat, well, sorry.

   Declaring the functions as static like this seems to be a bit more
   reliable than defining COMMON_DIGEST_FOR_OPENSSL on older cats. */
#  define my_md5_ctx CC_MD5_CTX

static CURLcode my_md5_init(void *ctx)
{
  (void)CC_MD5_Init(ctx);  /* always returns 1 */
  return CURLE_OK;
}

static void my_md5_update(void *ctx,
                          const unsigned char *input, unsigned int len)
{
  CC_MD5_Update(ctx, input, len);
}

static void my_md5_final(unsigned char *digest, void *ctx)
{
  CC_MD5_Final(digest, ctx);
}

#elif defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>

struct md5_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct md5_ctx my_md5_ctx;

static CURLcode my_md5_init(void *in)
{
  my_md5_ctx *ctx = (my_md5_ctx *)in;
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

static void my_md5_update(void *in,
                          const unsigned char *input, unsigned int len)
{
  my_md5_ctx *ctx = in;
  CryptHashData(ctx->hHash, (const BYTE *)input, len, 0);
}

static void my_md5_final(unsigned char *digest, void *in)
{
  my_md5_ctx *ctx = (my_md5_ctx *)in;
  unsigned long length = 0;
  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == MD5_DIGEST_LEN)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);
  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);
  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
}

#else
#error "MD5 support required but not offered by any TLS backend"
#endif /* CRYPTO LIBS */

const struct HMAC_params Curl_HMAC_MD5 = {
  my_md5_init,        /* Hash initialization function. */
  my_md5_update,      /* Hash update function. */
  my_md5_final,       /* Hash computation end function. */
  sizeof(my_md5_ctx), /* Size of hash context structure. */
  64,                 /* Maximum key length. */
  MD5_DIGEST_LEN      /* Result size. */
};

const struct MD5_params Curl_DIGEST_MD5 = {
  my_md5_init,        /* Digest initialization function */
  my_md5_update,      /* Digest update function */
  my_md5_final,       /* Digest computation end function */
  sizeof(my_md5_ctx), /* Size of digest context struct */
  MD5_DIGEST_LEN      /* Result size */
};

/*
 * @unittest: 1601
 * Returns CURLE_OK on success.
 */
CURLcode Curl_md5it(unsigned char *output,
                    const unsigned char *input, size_t len)
{
  CURLcode result;
  my_md5_ctx ctx;

  result = my_md5_init(&ctx);
  if(!result) {
    do {
      unsigned int ilen = (unsigned int)CURLMIN(len, UINT_MAX);
      my_md5_update(&ctx, input, ilen);
      input += ilen;
      len -= ilen;
    } while(len);
    my_md5_final(output, &ctx);
  }
  return result;
}

struct MD5_context *Curl_MD5_init(const struct MD5_params *md5params)
{
  struct MD5_context *ctxt;

  /* Create MD5 context */
  ctxt = curlx_malloc(sizeof(*ctxt));

  if(!ctxt)
    return ctxt;

  ctxt->md5_hashctx = curlx_malloc(md5params->md5_ctxtsize);

  if(!ctxt->md5_hashctx) {
    curlx_free(ctxt);
    return NULL;
  }

  ctxt->md5_hash = md5params;

  if((*md5params->md5_init_func)(ctxt->md5_hashctx)) {
    curlx_free(ctxt->md5_hashctx);
    curlx_free(ctxt);
    return NULL;
  }

  return ctxt;
}

CURLcode Curl_MD5_update(struct MD5_context *context,
                         const unsigned char *input, unsigned int len)
{
  (*context->md5_hash->md5_update_func)(context->md5_hashctx, input, len);

  return CURLE_OK;
}

CURLcode Curl_MD5_final(struct MD5_context *context, unsigned char *result)
{
  (*context->md5_hash->md5_final_func)(result, context->md5_hashctx);

  curlx_free(context->md5_hashctx);
  curlx_free(context);

  return CURLE_OK;
}

#endif /* Using NTLM (without SSPI) || Digest */
