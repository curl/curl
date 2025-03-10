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

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_DIGEST_AUTH) \
  || defined(USE_LIBSSH2) || defined(USE_SSL)

#include "warnless.h"
#include "curl_sha256.h"
#include "curl_hmac.h"

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#elif defined(USE_GNUTLS)
#include <nettle/sha.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/version.h>
#if(MBEDTLS_VERSION_NUMBER >= 0x02070000) && \
   (MBEDTLS_VERSION_NUMBER < 0x03000000)
  #define HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS
#endif
#include <mbedtls/sha256.h>
#elif (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
              (__MAC_OS_X_VERSION_MAX_ALLOWED >= 1040)) || \
      (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
              (__IPHONE_OS_VERSION_MAX_ALLOWED >= 20000))
#include <CommonCrypto/CommonDigest.h>
#define AN_APPLE_OS
#elif defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* Please keep the SSL backend-specific #if branches in this order:
 *
 * 1. USE_OPENSSL
 * 2. USE_GNUTLS
 * 3. USE_MBEDTLS
 * 4. USE_COMMON_CRYPTO
 * 5. USE_WIN32_CRYPTO
 *
 * This ensures that the same SSL branch gets activated throughout this source
 * file even if multiple backends are enabled at the same time.
 */

#ifdef USE_OPENSSL

struct ossl_sha256_ctx {
  EVP_MD_CTX *openssl_ctx;
};
typedef struct ossl_sha256_ctx my_sha256_ctx;

static CURLcode my_sha256_init(void *in)
{
  my_sha256_ctx *ctx = (my_sha256_ctx *)in;
  ctx->openssl_ctx = EVP_MD_CTX_create();
  if(!ctx->openssl_ctx)
    return CURLE_OUT_OF_MEMORY;

  if(!EVP_DigestInit_ex(ctx->openssl_ctx, EVP_sha256(), NULL)) {
    EVP_MD_CTX_destroy(ctx->openssl_ctx);
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
  EVP_MD_CTX_destroy(ctx->openssl_ctx);
}

#elif defined(USE_GNUTLS)

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
  sha256_digest(ctx, SHA256_DIGEST_SIZE, digest);
}

#elif defined(USE_MBEDTLS)

typedef mbedtls_sha256_context my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
#if !defined(HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS)
  (void) mbedtls_sha256_starts(ctx, 0);
#else
  (void) mbedtls_sha256_starts_ret(ctx, 0);
#endif
  return CURLE_OK;
}

static void my_sha256_update(void *ctx,
                             const unsigned char *data,
                             unsigned int length)
{
#if !defined(HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS)
  (void) mbedtls_sha256_update(ctx, data, length);
#else
  (void) mbedtls_sha256_update_ret(ctx, data, length);
#endif
}

static void my_sha256_final(unsigned char *digest, void *ctx)
{
#if !defined(HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS)
  (void) mbedtls_sha256_finish(ctx, digest);
#else
  (void) mbedtls_sha256_finish_ret(ctx, digest);
#endif
}

#elif defined(AN_APPLE_OS)
typedef CC_SHA256_CTX my_sha256_ctx;

static CURLcode my_sha256_init(void *ctx)
{
  (void) CC_SHA256_Init(ctx);
  return CURLE_OK;
}

static void my_sha256_update(void *ctx,
                             const unsigned char *data,
                             unsigned int length)
{
  (void) CC_SHA256_Update(ctx, data, length);
}

static void my_sha256_final(unsigned char *digest, void *ctx)
{
  (void) CC_SHA256_Final(digest, ctx);
}

#elif defined(USE_WIN32_CRYPTO)

struct sha256_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct sha256_ctx my_sha256_ctx;

#if !defined(CALG_SHA_256)
#define CALG_SHA_256 0x0000800c
#endif

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
#ifdef __MINGW32CE__
  CryptHashData(ctx->hHash, (BYTE *)CURL_UNCONST(data), length, 0);
#else
  CryptHashData(ctx->hHash, (const BYTE *)data, length, 0);
#endif
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

#else

/* When no other crypto library is available we use this code segment */

/* This is based on SHA256 implementation in LibTomCrypt that was released into
 * public domain by Tom St Denis. */

#define WPA_GET_BE32(a) ((((unsigned long)(a)[0]) << 24) | \
                         (((unsigned long)(a)[1]) << 16) | \
                         (((unsigned long)(a)[2]) <<  8) | \
                          ((unsigned long)(a)[3]))
#define WPA_PUT_BE32(a, val)                                        \
do {                                                                \
  (a)[0] = (unsigned char)((((unsigned long) (val)) >> 24) & 0xff); \
  (a)[1] = (unsigned char)((((unsigned long) (val)) >> 16) & 0xff); \
  (a)[2] = (unsigned char)((((unsigned long) (val)) >> 8) & 0xff);  \
  (a)[3] = (unsigned char)(((unsigned long) (val)) & 0xff);         \
} while(0)

#ifdef HAVE_LONGLONG
#define WPA_PUT_BE64(a, val)                                    \
do {                                                            \
  (a)[0] = (unsigned char)(((unsigned long long)(val)) >> 56);  \
  (a)[1] = (unsigned char)(((unsigned long long)(val)) >> 48);  \
  (a)[2] = (unsigned char)(((unsigned long long)(val)) >> 40);  \
  (a)[3] = (unsigned char)(((unsigned long long)(val)) >> 32);  \
  (a)[4] = (unsigned char)(((unsigned long long)(val)) >> 24);  \
  (a)[5] = (unsigned char)(((unsigned long long)(val)) >> 16);  \
  (a)[6] = (unsigned char)(((unsigned long long)(val)) >> 8);   \
  (a)[7] = (unsigned char)(((unsigned long long)(val)) & 0xff); \
} while(0)
#else
#define WPA_PUT_BE64(a, val)                                  \
do {                                                          \
  (a)[0] = (unsigned char)(((unsigned __int64)(val)) >> 56);  \
  (a)[1] = (unsigned char)(((unsigned __int64)(val)) >> 48);  \
  (a)[2] = (unsigned char)(((unsigned __int64)(val)) >> 40);  \
  (a)[3] = (unsigned char)(((unsigned __int64)(val)) >> 32);  \
  (a)[4] = (unsigned char)(((unsigned __int64)(val)) >> 24);  \
  (a)[5] = (unsigned char)(((unsigned __int64)(val)) >> 16);  \
  (a)[6] = (unsigned char)(((unsigned __int64)(val)) >> 8);   \
  (a)[7] = (unsigned char)(((unsigned __int64)(val)) & 0xff); \
} while(0)
#endif

struct sha256_state {
#ifdef HAVE_LONGLONG
  unsigned long long length;
#else
  unsigned __int64 length;
#endif
  unsigned long state[8], curlen;
  unsigned char buf[64];
};
typedef struct sha256_state my_sha256_ctx;

/* The K array */
static const unsigned long K[64] = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
  0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
  0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
  0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
  0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
  0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
  0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
  0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
  0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
  0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Various logical functions */
#define RORc(x, y) \
(((((unsigned long)(x) & 0xFFFFFFFFUL) >> (unsigned long)((y) & 31)) | \
   ((unsigned long)(x) << (unsigned long)(32 - ((y) & 31)))) & 0xFFFFFFFFUL)
#define Sha256_Ch(x,y,z)  (z ^ (x & (y ^ z)))
#define Sha256_Maj(x,y,z) (((x | y) & z) | (x & y))
#define Sha256_S(x, n)    RORc((x), (n))
#define Sha256_R(x, n)    (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)         (Sha256_S(x, 2) ^ Sha256_S(x, 13) ^ Sha256_S(x, 22))
#define Sigma1(x)         (Sha256_S(x, 6) ^ Sha256_S(x, 11) ^ Sha256_S(x, 25))
#define Gamma0(x)         (Sha256_S(x, 7) ^ Sha256_S(x, 18) ^ Sha256_R(x, 3))
#define Gamma1(x)         (Sha256_S(x, 17) ^ Sha256_S(x, 19) ^ Sha256_R(x, 10))

/* Compress 512-bits */
static int sha256_compress(struct sha256_state *md,
                           const unsigned char *buf)
{
  unsigned long S[8], W[64];
  int i;

  /* Copy state into S */
  for(i = 0; i < 8; i++) {
    S[i] = md->state[i];
  }
  /* copy the state into 512-bits into W[0..15] */
  for(i = 0; i < 16; i++)
    W[i] = WPA_GET_BE32(buf + (4 * i));
  /* fill W[16..63] */
  for(i = 16; i < 64; i++) {
    W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) +
      W[i - 16];
  }

  /* Compress */
#define RND(a,b,c,d,e,f,g,h,i)                                           \
  do {                                                                   \
    unsigned long t0 = h + Sigma1(e) + Sha256_Ch(e, f, g) + K[i] + W[i]; \
    unsigned long t1 = Sigma0(a) + Sha256_Maj(a, b, c);                  \
    d += t0;                                                             \
    h = t0 + t1;                                                         \
  } while(0)

  for(i = 0; i < 64; ++i) {
    unsigned long t;
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i);
    t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
    S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
  }

  /* Feedback */
  for(i = 0; i < 8; i++) {
    md->state[i] = md->state[i] + S[i];
  }

  return 0;
}

/* Initialize the hash state */
static CURLcode my_sha256_init(void *in)
{
  struct sha256_state *md = (struct sha256_state *)in;
  md->curlen = 0;
  md->length = 0;
  md->state[0] = 0x6A09E667UL;
  md->state[1] = 0xBB67AE85UL;
  md->state[2] = 0x3C6EF372UL;
  md->state[3] = 0xA54FF53AUL;
  md->state[4] = 0x510E527FUL;
  md->state[5] = 0x9B05688CUL;
  md->state[6] = 0x1F83D9ABUL;
  md->state[7] = 0x5BE0CD19UL;

  return CURLE_OK;
}

/*
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
static void my_sha256_update(void *ctx,
                             const unsigned char *in,
                             unsigned int len)
{
  unsigned long inlen = len;
  unsigned long n;
  struct sha256_state *md = (struct sha256_state *)ctx;
#define CURL_SHA256_BLOCK_SIZE 64
  if(md->curlen > sizeof(md->buf))
    return;
  while(inlen > 0) {
    if(md->curlen == 0 && inlen >= CURL_SHA256_BLOCK_SIZE) {
      if(sha256_compress(md, in) < 0)
        return;
      md->length += CURL_SHA256_BLOCK_SIZE * 8;
      in += CURL_SHA256_BLOCK_SIZE;
      inlen -= CURL_SHA256_BLOCK_SIZE;
    }
    else {
      n = CURLMIN(inlen, (CURL_SHA256_BLOCK_SIZE - md->curlen));
      memcpy(md->buf + md->curlen, in, n);
      md->curlen += n;
      in += n;
      inlen -= n;
      if(md->curlen == CURL_SHA256_BLOCK_SIZE) {
        if(sha256_compress(md, md->buf) < 0)
          return;
        md->length += 8 * CURL_SHA256_BLOCK_SIZE;
        md->curlen = 0;
      }
    }
  }
}

/*
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return 0 if successful
*/
static void my_sha256_final(unsigned char *out, void *ctx)
{
  struct sha256_state *md = ctx;
  int i;

  if(md->curlen >= sizeof(md->buf))
    return;

  /* Increase the length of the message */
  md->length += md->curlen * 8;

  /* Append the '1' bit */
  md->buf[md->curlen++] = (unsigned char)0x80;

  /* If the length is currently above 56 bytes we append zeros
   * then compress. Then we can fall back to padding zeros and length
   * encoding like normal.
   */
  if(md->curlen > 56) {
    while(md->curlen < 64) {
      md->buf[md->curlen++] = (unsigned char)0;
    }
    sha256_compress(md, md->buf);
    md->curlen = 0;
  }

  /* Pad up to 56 bytes of zeroes */
  while(md->curlen < 56) {
    md->buf[md->curlen++] = (unsigned char)0;
  }

  /* Store length */
  WPA_PUT_BE64(md->buf + 56, md->length);
  sha256_compress(md, md->buf);

  /* Copy output */
  for(i = 0; i < 8; i++)
    WPA_PUT_BE32(out + (4 * i), md->state[i]);
}

#endif /* CRYPTO LIBS */

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
                       const size_t length)
{
  CURLcode result;
  my_sha256_ctx ctx;

  result = my_sha256_init(&ctx);
  if(!result) {
    my_sha256_update(&ctx, input, curlx_uztoui(length));
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

#endif /* AWS, DIGEST, or libssh2 */
