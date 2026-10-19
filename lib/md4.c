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

#ifdef USE_CURL_NTLM_CORE

#include "curl_md4.h"

#ifdef USE_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(USE_AMISSL)
/* OpenSSL 3.0.0 marks the MD4 functions as deprecated */
#define OPENSSL_NO_MD4
#else
/* Cover also OPENSSL_NO_MD4 configured in OpenSSL */
#include <openssl/opensslconf.h>
#endif
#endif /* USE_OPENSSL */

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#endif

#if defined(USE_OPENSSL) && !defined(OPENSSL_NO_MD4)
#include <openssl/evp.h>

typedef EVP_MD_CTX *my_md4_ctx;

static int my_md4_init(my_md4_ctx *ctx)
{
  *ctx = EVP_MD_CTX_new();
  if(!*ctx)
    return 0;

  if(!EVP_DigestInit_ex(*ctx, EVP_md4(), NULL)) {
    EVP_MD_CTX_free(*ctx);
    return 0;
  }
  return 1;
}

static void my_md4_update(my_md4_ctx *ctx,
                          const unsigned char *input, unsigned int len)
{
  (void)EVP_DigestUpdate(*ctx, input, len);
}

static void my_md4_final(unsigned char *digest, my_md4_ctx *ctx)
{
  (void)EVP_DigestFinal_ex(*ctx, digest, NULL);
  EVP_MD_CTX_free(*ctx);
}

#elif defined(USE_WOLFSSL) && !defined(NO_MD4)
#include <wolfssl/wolfcrypt/md4.h>
#include <wolfssl/version.h>

#if LIBWOLFSSL_VERSION_HEX >= 0x05007006
typedef wc_Md4 my_md4_ctx;
#else
typedef Md4 my_md4_ctx;
#endif

static int my_md4_init(my_md4_ctx *ctx)
{
  wc_InitMd4(ctx);
  return 1;
}

static void my_md4_update(my_md4_ctx *ctx,
                          const void *input, unsigned long len)
{
  wc_Md4Update(ctx, input, (word32)len);
}

static void my_md4_final(unsigned char *digest, my_md4_ctx *ctx)
{
  wc_Md4Final(ctx, digest);
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

typedef CC_MD4_CTX my_md4_ctx;

static int my_md4_init(my_md4_ctx *ctx)
{
  return CC_MD4_Init(ctx);  /* always returns 1 */
}

static void my_md4_update(my_md4_ctx *ctx,
                          const void *input, unsigned long len)
{
  (void)CC_MD4_Update(ctx, input, (CC_LONG)len);
}

static void my_md4_final(unsigned char *digest, my_md4_ctx *ctx)
{
  (void)CC_MD4_Final(digest, ctx);
}

#elif defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>

struct md4_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct md4_ctx my_md4_ctx;

static int my_md4_init(my_md4_ctx *ctx)
{
  ctx->hCryptProv = 0;
  ctx->hHash = 0;

  if(!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return 0;

  if(!CryptCreateHash(ctx->hCryptProv, CALG_MD4, 0, 0, &ctx->hHash)) {
    CryptReleaseContext(ctx->hCryptProv, 0);
    ctx->hCryptProv = 0;
    return 0;
  }

  return 1;
}

static void my_md4_update(my_md4_ctx *ctx,
                          const void *input, unsigned long len)
{
  CryptHashData(ctx->hHash, (const BYTE *)input, (unsigned int)len, 0);
}

static void my_md4_final(unsigned char *digest, my_md4_ctx *ctx)
{
  unsigned long length = 0;

  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == MD4_DIGEST_LENGTH)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);

  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);

  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
}

#elif defined(USE_GNUTLS)
#include <nettle/md4.h>
#include <nettle/version.h>

typedef struct md4_ctx my_md4_ctx;

static int my_md4_init(my_md4_ctx *ctx)
{
  md4_init(ctx);
  return 1;
}

static void my_md4_update(my_md4_ctx *ctx,
                          const void *input, unsigned long len)
{
  md4_update(ctx, len, input);
}

static void my_md4_final(unsigned char *digest, my_md4_ctx *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  md4_digest(ctx, digest);
#else
  md4_digest(ctx, MD4_DIGEST_SIZE, digest);
#endif
}

#else
#error "MD4 support required but not offered by any TLS backend"
#endif /* CRYPTO LIBS */

CURLcode Curl_md4it(unsigned char *output,
                    const unsigned char *input, const size_t len)
{
  my_md4_ctx ctx;
  if(!my_md4_init(&ctx))
    return CURLE_FAILED_INIT;
  my_md4_update(&ctx, input, curlx_uztoui(len));
  my_md4_final(output, &ctx);
  return CURLE_OK;
}

#endif /* USE_CURL_NTLM_CORE */
