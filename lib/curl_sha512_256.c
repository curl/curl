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

/* Context type used for SHA-512/256 calculations */
typedef EVP_MD_CTX *Curl_sha512_256_ctx;

/* Initialize structure for SHA-512/256 calculation.
 *
 * @param pctx the calculation context
 * @return CURLE_OK if succeed, error code otherwise
 */
static CURLcode my_sha512_256_init(void *pctx)
{
  EVP_MD_CTX ** const ctx = pctx;

  *ctx = EVP_MD_CTX_new();
  if(!*ctx)
    return CURLE_OUT_OF_MEMORY;

  if(!EVP_DigestInit_ex(*ctx, EVP_sha512_256(), NULL)) {
    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;
    return CURLE_FAILED_INIT;
  }
  /* Check whether the header and this file use the same numbers */
  DEBUGASSERT(EVP_MD_CTX_size(*ctx) == CURL_SHA512_256_DIGEST_LENGTH);
  /* Check whether the block size is correct */
  DEBUGASSERT(EVP_MD_CTX_block_size(*ctx) == 128);
  return CURLE_OK;
}

/* Process portion of bytes.
 *
 * @param pctx the calculation context
 * @param input bytes to add to hash
 * @param input_len number of bytes in @a input
 * @return CURLE_OK if succeed, error code otherwise
 */
static CURLcode my_sha512_256_update(void *pctx,
                                     const void *input, size_t input_len)
{
  EVP_MD_CTX ** const ctx = pctx;
  return EVP_DigestUpdate(*ctx, input, input_len) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
}

/* Finalise SHA-512/256 calculation, return digest.
 *
 * @param[out] digest returned, must be #CURL_SHA512_256_DIGEST_LENGTH bytes
 * @param pctx the calculation context
 * @return CURLE_OK if succeed, error code otherwise
 */
static CURLcode my_sha512_256_final(uint8_t *digest, void *pctx)
{
  EVP_MD_CTX ** const ctx = pctx;
  CURLcode result;

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
#if defined(__NetBSD__) && \
  (__NetBSD_Version__ <   904000000 ||  \
   (__NetBSD_Version__ >=  999000000 &&  \
    __NetBSD_Version__ <  1000000000) || \
   (__NetBSD_Version__ >= 1099000000 &&  \
    __NetBSD_Version__ <  1099001100))
  /* Use a larger buffer to work around a bug in NetBSD:
     https://gnats.netbsd.org/cgi-bin/query-pr-single.pl?number=58039 */
  uint8_t tmp_digest[CURL_SHA512_256_DIGEST_LENGTH * 2];
  result = EVP_DigestFinal_ex(*ctx, tmp_digest, NULL) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
  if(result == CURLE_OK)
    memcpy(digest, tmp_digest, CURL_SHA512_256_DIGEST_LENGTH);
  curlx_memzero(tmp_digest, sizeof(tmp_digest));
#else
  result = EVP_DigestFinal_ex(*ctx, digest, NULL) ?
    CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
#endif

  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;

  return result;
}

#elif defined(USE_WOLFSSL_SHA512_256)
#include <wolfssl/wolfcrypt/sha512.h>

typedef struct wc_Sha512 Curl_sha512_256_ctx;

static CURLcode my_sha512_256_init(void *ctx)
{
  if(wc_InitSha512_256(ctx))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode my_sha512_256_update(void *ctx,
                                     const void *input, size_t input_len)
{
  const byte *bytes = input;
  do {
    word32 ilen = (word32)CURLMIN(input_len, UINT_MAX);
    if(wc_Sha512_256Update(ctx, bytes, ilen))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    input_len -= ilen;
    bytes += ilen;
  } while(input_len);
  return CURLE_OK;
}

static CURLcode my_sha512_256_final(uint8_t *digest, void *ctx)
{
  if(wc_Sha512_256Final(ctx, digest))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#elif defined(USE_GNUTLS_SHA512_256)

typedef struct sha512_256_ctx Curl_sha512_256_ctx;

static CURLcode my_sha512_256_init(void *ctx)
{
  sha512_256_init(ctx);
  return CURLE_OK;
}

static CURLcode my_sha512_256_update(void *ctx,
                                     const void *input, size_t input_len)
{
  DEBUGASSERT(input || (input_len == 0));
  sha512_256_update(ctx, input_len, input);
  return CURLE_OK;
}

static CURLcode my_sha512_256_final(uint8_t *digest, void *ctx)
{
#if NETTLE_VERSION_MAJOR >= 4
  sha512_256_digest(ctx, digest);
#else
  sha512_256_digest(ctx, CURL_SHA512_256_DIGEST_LENGTH, digest);
#endif
  return CURLE_OK;
}

#endif

/* Compute SHA-512/256 hash for the given data in one function call
 * @param[out] digest the pointer to put the hash
 * @param[in] input the pointer to the data to process
 * @param input_len the size of the data pointed by @a input
 * @return always #CURLE_OK
 */
CURLcode Curl_sha512_256it(uint8_t *digest,
                           const void *input, size_t input_len)
{
  Curl_sha512_256_ctx ctx;
  CURLcode result = my_sha512_256_init(&ctx);
  if(result)
    return result;

  result = my_sha512_256_update(&ctx, input, input_len);
  if(result) {
    (void)my_sha512_256_final(digest, &ctx);
    return result;
  }

  return my_sha512_256_final(digest, &ctx);
}

#endif /* CURL_HAVE_SHA512_256 */

#endif /* !CURL_DISABLE_DIGEST_AUTH && !CURL_DISABLE_SHA512_256 */
