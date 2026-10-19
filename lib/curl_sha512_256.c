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

#include "curl_sha512_256.h"

#ifdef CURL_HAVE_SHA512_256

#ifdef USE_OPENSSL_SHA512_256

/* OpenSSL does not provide macros for SHA-512/256 sizes */

/* Size of the SHA-512/256 single processing block in bytes. */
#define CURL_SHA512_256_BLOCK_SIZE 128

/* Size of the SHA-512/256 resulting digest in bytes.
   This is the final digest size, not intermediate hash. */
#define CURL_SHA512_256_DIGEST_SIZE CURL_SHA512_256_DIGEST_LENGTH

/* Context type used for SHA-512/256 calculations */
typedef EVP_MD_CTX *Curl_sha512_256_ctx;

/**
 * Initialize structure for SHA-512/256 calculation.
 *
 * @param context the calculation context
 * @return CURLE_OK if succeed,
 *         error code otherwise
 */
static CURLcode Curl_sha512_256_init(void *context)
{
  Curl_sha512_256_ctx * const ctx = (Curl_sha512_256_ctx *)context;

  *ctx = EVP_MD_CTX_new();
  if(!*ctx)
    return CURLE_OUT_OF_MEMORY;

  if(EVP_DigestInit_ex(*ctx, EVP_sha512_256(), NULL)) {
    /* Check whether the header and this file use the same numbers */
    DEBUGASSERT(EVP_MD_CTX_size(*ctx) == CURL_SHA512_256_DIGEST_SIZE);
    /* Check whether the block size is correct */
    DEBUGASSERT(EVP_MD_CTX_block_size(*ctx) == CURL_SHA512_256_BLOCK_SIZE);

    return CURLE_OK; /* Success */
  }

  /* Cleanup */
  EVP_MD_CTX_free(*ctx);
  return CURLE_FAILED_INIT;
}

/**
 * Process portion of bytes.
 *
 * @param context the calculation context
 * @param data bytes to add to hash
 * @return CURLE_OK if succeed,
 *         error code otherwise
 */
static CURLcode Curl_sha512_256_update(void *context,
                                       const unsigned char *data,
                                       size_t length)
{
  Curl_sha512_256_ctx * const ctx = (Curl_sha512_256_ctx *)context;

  if(!EVP_DigestUpdate(*ctx, data, length))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  return CURLE_OK;
}

/**
 * Finalise SHA-512/256 calculation, return digest.
 *
 * @param context the calculation context
 * @param[out] digest set to the hash, must be #CURL_SHA512_256_DIGEST_SIZE
 *             bytes
 * @return CURLE_OK if succeed,
 *         error code otherwise
 */
#ifdef __NetBSD__
/* Some NetBSD versions have a bug in SHA-512/256.
 * See https://gnats.netbsd.org/cgi-bin/query-pr-single.pl?number=58039
 * The problematic versions:
 * - NetBSD before 9.4
 * - NetBSD 9 all development versions (9.99.x)
 * - NetBSD 10 development versions (10.99.x) before 10.99.11
 * The bug was fixed in NetBSD 9.4 release, NetBSD 10.0 release,
 * NetBSD 10.99.11 development.
 * It is safe to apply the workaround even if the bug is not present, as
 * the workaround reduces performance slightly. */
#  if  __NetBSD_Version__ <   904000000 ||  \
      (__NetBSD_Version__ >=  999000000 &&  \
       __NetBSD_Version__ <  1000000000) || \
      (__NetBSD_Version__ >= 1099000000 &&  \
       __NetBSD_Version__ <  1099001100)
#    define NEED_NETBSD_SHA512_256_WORKAROUND 1
#  endif
#endif
static CURLcode Curl_sha512_256_finish(unsigned char *digest, void *context)
{
  CURLcode result;
  Curl_sha512_256_ctx * const ctx = (Curl_sha512_256_ctx *)context;

#ifdef NEED_NETBSD_SHA512_256_WORKAROUND
  /* Use a larger buffer to work around a bug in NetBSD:
     https://gnats.netbsd.org/cgi-bin/query-pr-single.pl?number=58039 */
  unsigned char tmp_digest[CURL_SHA512_256_DIGEST_SIZE * 2];
  result = EVP_DigestFinal_ex(*ctx, tmp_digest, NULL) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
  if(result == CURLE_OK)
    memcpy(digest, tmp_digest, CURL_SHA512_256_DIGEST_SIZE);
  curlx_memzero(tmp_digest, sizeof(tmp_digest));
#else /* !NEED_NETBSD_SHA512_256_WORKAROUND */
  result = EVP_DigestFinal_ex(*ctx, digest, NULL) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
#endif /* NEED_NETBSD_SHA512_256_WORKAROUND */

  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;

  return result;
}

#elif defined(USE_WOLFSSL_SHA512_256)
#include <wolfssl/wolfcrypt/sha512.h>

#define CURL_SHA512_256_DIGEST_SIZE WC_SHA512_256_DIGEST_SIZE
#define CURL_SHA512_256_BLOCK_SIZE  WC_SHA512_256_BLOCK_SIZE

typedef struct wc_Sha512 Curl_sha512_256_ctx;

static CURLcode Curl_sha512_256_init(void *ctx)
{
  if(wc_InitSha512_256(ctx))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode Curl_sha512_256_update(void *ctx,
                                       const unsigned char *data,
                                       size_t length)
{
  do {
    word32 ilen = (word32)CURLMIN(length, UINT_MAX);
    if(wc_Sha512_256Update(ctx, data, ilen))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    length -= ilen;
    data += ilen;
  } while(length);
  return CURLE_OK;
}

static CURLcode Curl_sha512_256_finish(unsigned char *digest, void *ctx)
{
  if(wc_Sha512_256Final(ctx, digest))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#elif defined(USE_GNUTLS_SHA512_256)

#define CURL_SHA512_256_BLOCK_SIZE  SHA512_256_BLOCK_SIZE
#define CURL_SHA512_256_DIGEST_SIZE SHA512_256_DIGEST_SIZE

/* Context type used for SHA-512/256 calculations */
typedef struct sha512_256_ctx Curl_sha512_256_ctx;

/**
 * Initialize structure for SHA-512/256 calculation.
 *
 * @param context the calculation context
 * @return always CURLE_OK
 */
static CURLcode Curl_sha512_256_init(void *context)
{
  Curl_sha512_256_ctx * const ctx = (Curl_sha512_256_ctx *)context;

  /* Check whether the header and this file use the same numbers */
  DEBUGASSERT(CURL_SHA512_256_DIGEST_LENGTH == CURL_SHA512_256_DIGEST_SIZE);

  sha512_256_init(ctx);

  return CURLE_OK;
}

/**
 * Process portion of bytes.
 *
 * @param context the calculation context
 * @param data bytes to add to hash
 * @param length number of bytes in @a data
 * @return always CURLE_OK
 */
static CURLcode Curl_sha512_256_update(void *context,
                                       const unsigned char *data,
                                       size_t length)
{
  Curl_sha512_256_ctx * const ctx = (Curl_sha512_256_ctx *)context;

  DEBUGASSERT(data || (length == 0));

  sha512_256_update(ctx, length, (const uint8_t *)data);

  return CURLE_OK;
}

/**
 * Finalise SHA-512/256 calculation, return digest.
 *
 * @param context the calculation context
 * @param[out] digest set to the hash, must be #CURL_SHA512_256_DIGEST_SIZE
 *             bytes
 * @return always CURLE_OK
 */
static CURLcode Curl_sha512_256_finish(unsigned char *digest, void *context)
{
  Curl_sha512_256_ctx * const ctx = (Curl_sha512_256_ctx *)context;

#if NETTLE_VERSION_MAJOR >= 4
  sha512_256_digest(ctx, (uint8_t *)digest);
#else
  sha512_256_digest(ctx,
                    (size_t)CURL_SHA512_256_DIGEST_SIZE, (uint8_t *)digest);
#endif

  return CURLE_OK;
}

#endif

/**
 * Compute SHA-512/256 hash for the given data in one function call
 * @param[out] output the pointer to put the hash
 * @param[in] input the pointer to the data to process
 * @param input_size the size of the data pointed by @a input
 * @return always #CURLE_OK
 */
CURLcode Curl_sha512_256it(unsigned char *output, const unsigned char *input,
                           size_t input_size)
{
  Curl_sha512_256_ctx ctx;
  CURLcode result;

  result = Curl_sha512_256_init(&ctx);
  if(result != CURLE_OK)
    return result;

  result = Curl_sha512_256_update(&ctx, (const void *)input, input_size);

  if(result != CURLE_OK) {
    (void)Curl_sha512_256_finish(output, &ctx);
    return result;
  }

  return Curl_sha512_256_finish(output, &ctx);
}

/* Wrapper function, takes 'unsigned int' as length type, returns void */
static void Curl_sha512_256_update_i(void *context,
                                     const unsigned char *data,
                                     unsigned int length)
{
  /* Hypothetically the function may fail, but assume it does not */
  (void)Curl_sha512_256_update(context, data, length);
}

/* Wrapper function, returns void */
static void Curl_sha512_256_finish_v(unsigned char *result, void *context)
{
  /* Hypothetically the function may fail, but assume it does not */
  (void)Curl_sha512_256_finish(result, context);
}

/* Wrapper function, takes 'unsigned int' as length type, returns void */

const struct HMAC_params Curl_HMAC_SHA512_256[] = {
  {
    /* Initialize context procedure. */
    Curl_sha512_256_init,
    /* Update context with data. */
    Curl_sha512_256_update_i,
    /* Get final result procedure. */
    Curl_sha512_256_finish_v,
    /* Context structure size. */
    sizeof(Curl_sha512_256_ctx),
    /* Maximum key length (bytes). */
    CURL_SHA512_256_BLOCK_SIZE,
    /* Result length (bytes). */
    CURL_SHA512_256_DIGEST_SIZE
  }
};

#endif /* CURL_HAVE_SHA512_256 */
#endif /* !CURL_DISABLE_DIGEST_AUTH && !CURL_DISABLE_SHA512_256 */
