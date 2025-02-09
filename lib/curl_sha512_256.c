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
#include "warnless.h"

/* The recommended order of the TLS backends:
 * * OpenSSL
 * * GnuTLS
 * * wolfSSL
 * * Schannel SSPI
 * * Secure Transport (Darwin)
 * * mbedTLS
 * * BearSSL
 * * Rustls
 * Skip the backend if it does not support the required algorithm */

#if defined(USE_OPENSSL)
#  include <openssl/opensslv.h>
#  if (!defined(LIBRESSL_VERSION_NUMBER) && \
        defined(OPENSSL_VERSION_NUMBER) && \
        (OPENSSL_VERSION_NUMBER >= 0x10101000L)) || \
      (defined(LIBRESSL_VERSION_NUMBER) && \
        (LIBRESSL_VERSION_NUMBER >= 0x3080000fL))
#    include <openssl/opensslconf.h>
#    if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA512)
#      include <openssl/evp.h>
#      define USE_OPENSSL_SHA512_256          1
#      define HAS_SHA512_256_IMPLEMENTATION   1
#      ifdef __NetBSD__
/* Some NetBSD versions has a bug in SHA-512/256.
 * See https://gnats.netbsd.org/cgi-bin/query-pr-single.pl?number=58039
 * The problematic versions:
 * - NetBSD before 9.4
 * - NetBSD 9 all development versions (9.99.x)
 * - NetBSD 10 development versions (10.99.x) before 10.99.11
 * The bug was fixed in NetBSD 9.4 release, NetBSD 10.0 release,
 * NetBSD 10.99.11 development.
 * It is safe to apply the workaround even if the bug is not present, as
 * the workaround just reduces performance slightly. */
#        include <sys/param.h>
#        if  __NetBSD_Version__ <   904000000 ||  \
            (__NetBSD_Version__ >=  999000000 &&  \
             __NetBSD_Version__ <  1000000000) || \
            (__NetBSD_Version__ >= 1099000000 &&  \
             __NetBSD_Version__ <  1099001100)
#          define NEED_NETBSD_SHA512_256_WORKAROUND 1
#          include <string.h>
#        endif
#      endif
#    endif
#  endif
#endif /* USE_OPENSSL */


#if !defined(HAS_SHA512_256_IMPLEMENTATION) && defined(USE_GNUTLS)
#  include <nettle/sha.h>
#  if defined(SHA512_256_DIGEST_SIZE)
#    define USE_GNUTLS_SHA512_256           1
#  endif
#endif /* ! HAS_SHA512_256_IMPLEMENTATION && USE_GNUTLS */

#if defined(USE_OPENSSL_SHA512_256)

/* OpenSSL does not provide macros for SHA-512/256 sizes */

/**
 * Size of the SHA-512/256 single processing block in bytes.
 */
#define CURL_SHA512_256_BLOCK_SIZE 128

/**
 * Size of the SHA-512/256 resulting digest in bytes.
 * This is the final digest size, not intermediate hash.
 */
#define CURL_SHA512_256_DIGEST_SIZE CURL_SHA512_256_DIGEST_LENGTH

/**
 * Context type used for SHA-512/256 calculations
 */
typedef EVP_MD_CTX *Curl_sha512_256_ctx;

/**
 * Initialise structure for SHA-512/256 calculation.
 *
 * @param context the calculation context
 * @return CURLE_OK if succeed,
 *         error code otherwise
 */
static CURLcode
Curl_sha512_256_init(void *context)
{
  Curl_sha512_256_ctx *const ctx = (Curl_sha512_256_ctx *)context;

  *ctx = EVP_MD_CTX_create();
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
  EVP_MD_CTX_destroy(*ctx);
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
static CURLcode
Curl_sha512_256_update(void *context,
                       const unsigned char *data,
                       size_t length)
{
  Curl_sha512_256_ctx *const ctx = (Curl_sha512_256_ctx *)context;

  if(!EVP_DigestUpdate(*ctx, data, length))
    return CURLE_SSL_CIPHER;

  return CURLE_OK;
}


/**
 * Finalise SHA-512/256 calculation, return digest.
 *
 * @param context the calculation context
 * @param[out] digest set to the hash, must be #CURL_SHA512_256_DIGEST_SIZE
 #             bytes
 * @return CURLE_OK if succeed,
 *         error code otherwise
 */
static CURLcode
Curl_sha512_256_finish(unsigned char *digest,
                       void *context)
{
  CURLcode ret;
  Curl_sha512_256_ctx *const ctx = (Curl_sha512_256_ctx *)context;

#ifdef NEED_NETBSD_SHA512_256_WORKAROUND
  /* Use a larger buffer to work around a bug in NetBSD:
     https://gnats.netbsd.org/cgi-bin/query-pr-single.pl?number=58039 */
  unsigned char tmp_digest[CURL_SHA512_256_DIGEST_SIZE * 2];
  ret = EVP_DigestFinal_ex(*ctx,
                           tmp_digest, NULL) ? CURLE_OK : CURLE_SSL_CIPHER;
  if(ret == CURLE_OK)
    memcpy(digest, tmp_digest, CURL_SHA512_256_DIGEST_SIZE);
  explicit_memset(tmp_digest, 0, sizeof(tmp_digest));
#else  /* ! NEED_NETBSD_SHA512_256_WORKAROUND */
  ret = EVP_DigestFinal_ex(*ctx, digest, NULL) ? CURLE_OK : CURLE_SSL_CIPHER;
#endif /* ! NEED_NETBSD_SHA512_256_WORKAROUND */

  EVP_MD_CTX_destroy(*ctx);
  *ctx = NULL;

  return ret;
}

#elif defined(USE_GNUTLS_SHA512_256)

#define CURL_SHA512_256_BLOCK_SIZE  SHA512_256_BLOCK_SIZE
#define CURL_SHA512_256_DIGEST_SIZE SHA512_256_DIGEST_SIZE

/**
 * Context type used for SHA-512/256 calculations
 */
typedef struct sha512_256_ctx Curl_sha512_256_ctx;

/**
 * Initialise structure for SHA-512/256 calculation.
 *
 * @param context the calculation context
 * @return always CURLE_OK
 */
static CURLcode
Curl_sha512_256_init(void *context)
{
  Curl_sha512_256_ctx *const ctx = (Curl_sha512_256_ctx *)context;

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
static CURLcode
Curl_sha512_256_update(void *context,
                       const unsigned char *data,
                       size_t length)
{
  Curl_sha512_256_ctx *const ctx = (Curl_sha512_256_ctx *)context;

  DEBUGASSERT((data != NULL) || (length == 0));

  sha512_256_update(ctx, length, (const uint8_t *)data);

  return CURLE_OK;
}


/**
 * Finalise SHA-512/256 calculation, return digest.
 *
 * @param context the calculation context
 * @param[out] digest set to the hash, must be #CURL_SHA512_256_DIGEST_SIZE
 #             bytes
 * @return always CURLE_OK
 */
static CURLcode
Curl_sha512_256_finish(unsigned char *digest,
                       void *context)
{
  Curl_sha512_256_ctx *const ctx = (Curl_sha512_256_ctx *)context;

  sha512_256_digest(ctx,
                    (size_t)CURL_SHA512_256_DIGEST_SIZE, (uint8_t *)digest);

  return CURLE_OK;
}

#else /* No system or TLS backend SHA-512/256 implementation available */

/* ** This implementation of SHA-512/256 hash calculation was originally ** *
 * ** written by Evgeny Grin (Karlson2k) for GNU libmicrohttpd.          ** *
 * ** The author ported the code to libcurl. The ported code is provided ** *
 * ** under curl license.                                                ** *
 * ** This is a minimal version with minimal optimizations. Performance  ** *
 * ** can be significantly improved. Big-endian store and load macros    ** *
 * ** are obvious targets for optimization.                              ** */

#ifdef __GNUC__
#  if defined(__has_attribute) && defined(__STDC_VERSION__)
#    if __has_attribute(always_inline) && __STDC_VERSION__ >= 199901
#      define CURL_FORCEINLINE CURL_INLINE __attribute__((always_inline))
#    endif
#  endif
#endif

#if !defined(CURL_FORCEINLINE) && \
  defined(_MSC_VER) && !defined(__GNUC__) && !defined(__clang__)
#  define CURL_FORCEINLINE __forceinline
#endif

#if !defined(CURL_FORCEINLINE)
   /* Assume that 'CURL_INLINE' keyword works or the
    * macro was already defined correctly. */
#  define CURL_FORCEINLINE CURL_INLINE
#endif

/* Bits manipulation macros and functions.
   Can be moved to other headers to reuse. */

#define CURL_GET_64BIT_BE(ptr)                                  \
  ( ((curl_uint64_t)(((const unsigned char*)(ptr))[0]) << 56) | \
    ((curl_uint64_t)(((const unsigned char*)(ptr))[1]) << 48) | \
    ((curl_uint64_t)(((const unsigned char*)(ptr))[2]) << 40) | \
    ((curl_uint64_t)(((const unsigned char*)(ptr))[3]) << 32) | \
    ((curl_uint64_t)(((const unsigned char*)(ptr))[4]) << 24) | \
    ((curl_uint64_t)(((const unsigned char*)(ptr))[5]) << 16) | \
    ((curl_uint64_t)(((const unsigned char*)(ptr))[6]) << 8)  | \
    (curl_uint64_t)(((const unsigned char*)(ptr))[7]) )

#define CURL_PUT_64BIT_BE(ptr,val) do {                                 \
    ((unsigned char*)(ptr))[7]=(unsigned char)((curl_uint64_t)(val));   \
    ((unsigned char*)(ptr))[6]=(unsigned char)(((curl_uint64_t)(val)) >> 8); \
    ((unsigned char*)(ptr))[5]=(unsigned char)(((curl_uint64_t)(val)) >> 16); \
    ((unsigned char*)(ptr))[4]=(unsigned char)(((curl_uint64_t)(val)) >> 24); \
    ((unsigned char*)(ptr))[3]=(unsigned char)(((curl_uint64_t)(val)) >> 32); \
    ((unsigned char*)(ptr))[2]=(unsigned char)(((curl_uint64_t)(val)) >> 40); \
    ((unsigned char*)(ptr))[1]=(unsigned char)(((curl_uint64_t)(val)) >> 48); \
    ((unsigned char*)(ptr))[0]=(unsigned char)(((curl_uint64_t)(val)) >> 56); \
  } while(0)

/* Defined as a function. The macro version may duplicate the binary code
 * size as each argument is used twice, so if any calculation is used
 * as an argument, the calculation could be done twice. */
static CURL_FORCEINLINE curl_uint64_t
Curl_rotr64(curl_uint64_t value, unsigned int bits)
{
  bits %= 64;
  if(0 == bits)
    return value;
  /* Defined in a form which modern compiler could optimize. */
  return (value >> bits) | (value << (64 - bits));
}

/* SHA-512/256 specific data */

/**
 * Number of bits in a single SHA-512/256 word.
 */
#define SHA512_256_WORD_SIZE_BITS 64

/**
 * Number of bytes in a single SHA-512/256 word.
 */
#define SHA512_256_BYTES_IN_WORD (SHA512_256_WORD_SIZE_BITS / 8)

/**
 * Hash is kept internally as 8 64-bit words.
 * This is the intermediate hash size, used during computing the final digest.
 */
#define SHA512_256_HASH_SIZE_WORDS 8

/**
 * Size of the SHA-512/256 resulting digest in words.
 * This is the final digest size, not intermediate hash.
 */
#define SHA512_256_DIGEST_SIZE_WORDS (SHA512_256_HASH_SIZE_WORDS  / 2)

/**
 * Size of the SHA-512/256 resulting digest in bytes
 * This is the final digest size, not intermediate hash.
 */
#define CURL_SHA512_256_DIGEST_SIZE \
  (SHA512_256_DIGEST_SIZE_WORDS * SHA512_256_BYTES_IN_WORD)

/**
 * Size of the SHA-512/256 single processing block in bits.
 */
#define SHA512_256_BLOCK_SIZE_BITS 1024

/**
 * Size of the SHA-512/256 single processing block in bytes.
 */
#define CURL_SHA512_256_BLOCK_SIZE (SHA512_256_BLOCK_SIZE_BITS / 8)

/**
 * Size of the SHA-512/256 single processing block in words.
 */
#define SHA512_256_BLOCK_SIZE_WORDS \
  (SHA512_256_BLOCK_SIZE_BITS / SHA512_256_WORD_SIZE_BITS)

/**
 * SHA-512/256 calculation context
 */
struct Curl_sha512_256ctx
{
  /**
   * Intermediate hash value. The variable is properly aligned. Smart
   * compilers may automatically use fast load/store instruction for big
   * endian data on little endian machine.
   */
  curl_uint64_t H[SHA512_256_HASH_SIZE_WORDS];
  /**
   * SHA-512/256 input data buffer. The buffer is properly aligned. Smart
   * compilers may automatically use fast load/store instruction for big
   * endian data on little endian machine.
   */
  curl_uint64_t buffer[SHA512_256_BLOCK_SIZE_WORDS];
  /**
   * The number of bytes, lower part
   */
  curl_uint64_t count;
  /**
   * The number of bits, high part. Unlike lower part, this counts the number
   * of bits, not bytes.
   */
  curl_uint64_t count_bits_hi;
};

/**
 * Context type used for SHA-512/256 calculations
 */
typedef struct Curl_sha512_256ctx Curl_sha512_256_ctx;


/**
 * Initialise structure for SHA-512/256 calculation.
 *
 * @param context the calculation context
 * @return always CURLE_OK
 */
static CURLcode
Curl_sha512_256_init(void *context)
{
  struct Curl_sha512_256ctx *const ctx = (struct Curl_sha512_256ctx *)context;

  /* Check whether the header and this file use the same numbers */
  DEBUGASSERT(CURL_SHA512_256_DIGEST_LENGTH == CURL_SHA512_256_DIGEST_SIZE);

  DEBUGASSERT(sizeof(curl_uint64_t) == 8);

  /* Initial hash values, see FIPS PUB 180-4 section 5.3.6.2 */
  /* Values generated by "IV Generation Function" as described in
   * section 5.3.6 */
  ctx->H[0] = CURL_UINT64_C(0x22312194FC2BF72C);
  ctx->H[1] = CURL_UINT64_C(0x9F555FA3C84C64C2);
  ctx->H[2] = CURL_UINT64_C(0x2393B86B6F53B151);
  ctx->H[3] = CURL_UINT64_C(0x963877195940EABD);
  ctx->H[4] = CURL_UINT64_C(0x96283EE2A88EFFE3);
  ctx->H[5] = CURL_UINT64_C(0xBE5E1E2553863992);
  ctx->H[6] = CURL_UINT64_C(0x2B0199FC2C85B8AA);
  ctx->H[7] = CURL_UINT64_C(0x0EB72DDC81C52CA2);

  /* Initialise number of bytes and high part of number of bits. */
  ctx->count = CURL_UINT64_C(0);
  ctx->count_bits_hi = CURL_UINT64_C(0);

  return CURLE_OK;
}


/**
 * Base of the SHA-512/256 transformation.
 * Gets a full 128 bytes block of data and updates hash values;
 * @param H     hash values
 * @param data  the data buffer with #CURL_SHA512_256_BLOCK_SIZE bytes block
 */
static void
Curl_sha512_256_transform(curl_uint64_t H[SHA512_256_HASH_SIZE_WORDS],
                          const void *data)
{
  /* Working variables,
     see FIPS PUB 180-4 section 6.7, 6.4. */
  curl_uint64_t a = H[0];
  curl_uint64_t b = H[1];
  curl_uint64_t c = H[2];
  curl_uint64_t d = H[3];
  curl_uint64_t e = H[4];
  curl_uint64_t f = H[5];
  curl_uint64_t g = H[6];
  curl_uint64_t h = H[7];

  /* Data buffer, used as a cyclic buffer.
     See FIPS PUB 180-4 section 5.2.2, 6.7, 6.4. */
  curl_uint64_t W[16];

  /* 'Ch' and 'Maj' macro functions are defined with widely-used optimization.
     See FIPS PUB 180-4 formulae 4.8, 4.9. */
#define Sha512_Ch(x,y,z)     ( (z) ^ ((x) & ((y) ^ (z))) )
#define Sha512_Maj(x,y,z)    ( ((x) & (y)) ^ ((z) & ((x) ^ (y))) )

  /* Four 'Sigma' macro functions.
     See FIPS PUB 180-4 formulae 4.10, 4.11, 4.12, 4.13. */
#define SIG0(x)                                                         \
  ( Curl_rotr64((x), 28) ^ Curl_rotr64((x), 34) ^ Curl_rotr64((x), 39) )
#define SIG1(x)                                                         \
  ( Curl_rotr64((x), 14) ^ Curl_rotr64((x), 18) ^ Curl_rotr64((x), 41) )
#define sig0(x)                                                 \
  ( Curl_rotr64((x), 1) ^ Curl_rotr64((x), 8) ^ ((x) >> 7) )
#define sig1(x)                                                 \
  ( Curl_rotr64((x), 19) ^ Curl_rotr64((x), 61) ^ ((x) >> 6) )

  if(1) {
    unsigned int t;
    /* K constants array.
       See FIPS PUB 180-4 section 4.2.3 for K values. */
    static const curl_uint64_t K[80] = {
      CURL_UINT64_C(0x428a2f98d728ae22), CURL_UINT64_C(0x7137449123ef65cd),
      CURL_UINT64_C(0xb5c0fbcfec4d3b2f), CURL_UINT64_C(0xe9b5dba58189dbbc),
      CURL_UINT64_C(0x3956c25bf348b538), CURL_UINT64_C(0x59f111f1b605d019),
      CURL_UINT64_C(0x923f82a4af194f9b), CURL_UINT64_C(0xab1c5ed5da6d8118),
      CURL_UINT64_C(0xd807aa98a3030242), CURL_UINT64_C(0x12835b0145706fbe),
      CURL_UINT64_C(0x243185be4ee4b28c), CURL_UINT64_C(0x550c7dc3d5ffb4e2),
      CURL_UINT64_C(0x72be5d74f27b896f), CURL_UINT64_C(0x80deb1fe3b1696b1),
      CURL_UINT64_C(0x9bdc06a725c71235), CURL_UINT64_C(0xc19bf174cf692694),
      CURL_UINT64_C(0xe49b69c19ef14ad2), CURL_UINT64_C(0xefbe4786384f25e3),
      CURL_UINT64_C(0x0fc19dc68b8cd5b5), CURL_UINT64_C(0x240ca1cc77ac9c65),
      CURL_UINT64_C(0x2de92c6f592b0275), CURL_UINT64_C(0x4a7484aa6ea6e483),
      CURL_UINT64_C(0x5cb0a9dcbd41fbd4), CURL_UINT64_C(0x76f988da831153b5),
      CURL_UINT64_C(0x983e5152ee66dfab), CURL_UINT64_C(0xa831c66d2db43210),
      CURL_UINT64_C(0xb00327c898fb213f), CURL_UINT64_C(0xbf597fc7beef0ee4),
      CURL_UINT64_C(0xc6e00bf33da88fc2), CURL_UINT64_C(0xd5a79147930aa725),
      CURL_UINT64_C(0x06ca6351e003826f), CURL_UINT64_C(0x142929670a0e6e70),
      CURL_UINT64_C(0x27b70a8546d22ffc), CURL_UINT64_C(0x2e1b21385c26c926),
      CURL_UINT64_C(0x4d2c6dfc5ac42aed), CURL_UINT64_C(0x53380d139d95b3df),
      CURL_UINT64_C(0x650a73548baf63de), CURL_UINT64_C(0x766a0abb3c77b2a8),
      CURL_UINT64_C(0x81c2c92e47edaee6), CURL_UINT64_C(0x92722c851482353b),
      CURL_UINT64_C(0xa2bfe8a14cf10364), CURL_UINT64_C(0xa81a664bbc423001),
      CURL_UINT64_C(0xc24b8b70d0f89791), CURL_UINT64_C(0xc76c51a30654be30),
      CURL_UINT64_C(0xd192e819d6ef5218), CURL_UINT64_C(0xd69906245565a910),
      CURL_UINT64_C(0xf40e35855771202a), CURL_UINT64_C(0x106aa07032bbd1b8),
      CURL_UINT64_C(0x19a4c116b8d2d0c8), CURL_UINT64_C(0x1e376c085141ab53),
      CURL_UINT64_C(0x2748774cdf8eeb99), CURL_UINT64_C(0x34b0bcb5e19b48a8),
      CURL_UINT64_C(0x391c0cb3c5c95a63), CURL_UINT64_C(0x4ed8aa4ae3418acb),
      CURL_UINT64_C(0x5b9cca4f7763e373), CURL_UINT64_C(0x682e6ff3d6b2b8a3),
      CURL_UINT64_C(0x748f82ee5defb2fc), CURL_UINT64_C(0x78a5636f43172f60),
      CURL_UINT64_C(0x84c87814a1f0ab72), CURL_UINT64_C(0x8cc702081a6439ec),
      CURL_UINT64_C(0x90befffa23631e28), CURL_UINT64_C(0xa4506cebde82bde9),
      CURL_UINT64_C(0xbef9a3f7b2c67915), CURL_UINT64_C(0xc67178f2e372532b),
      CURL_UINT64_C(0xca273eceea26619c), CURL_UINT64_C(0xd186b8c721c0c207),
      CURL_UINT64_C(0xeada7dd6cde0eb1e), CURL_UINT64_C(0xf57d4f7fee6ed178),
      CURL_UINT64_C(0x06f067aa72176fba), CURL_UINT64_C(0x0a637dc5a2c898a6),
      CURL_UINT64_C(0x113f9804bef90dae), CURL_UINT64_C(0x1b710b35131c471b),
      CURL_UINT64_C(0x28db77f523047d84), CURL_UINT64_C(0x32caab7b40c72493),
      CURL_UINT64_C(0x3c9ebe0a15c9bebc), CURL_UINT64_C(0x431d67c49c100d4c),
      CURL_UINT64_C(0x4cc5d4becb3e42b6), CURL_UINT64_C(0x597f299cfc657e2a),
      CURL_UINT64_C(0x5fcb6fab3ad6faec), CURL_UINT64_C(0x6c44198c4a475817)
    };

    /* One step of SHA-512/256 computation,
       see FIPS PUB 180-4 section 6.4.2 step 3.
       * Note: this macro updates working variables in-place, without rotation.
       * Note: the first (vH += SIG1(vE) + Ch(vE,vF,vG) + kt + wt) equals T1 in
       FIPS PUB 180-4 section 6.4.2 step 3.
       the second (vH += SIG0(vA) + Maj(vE,vF,vC) equals T1 + T2 in
       FIPS PUB 180-4 section 6.4.2 step 3.
       * Note: 'wt' must be used exactly one time in this macro as macro for
       'wt' calculation may change other data as well every time when
       used. */
#define SHA2STEP64(vA,vB,vC,vD,vE,vF,vG,vH,kt,wt) do {                       \
     (vD) += ((vH) += SIG1((vE)) + Sha512_Ch((vE),(vF),(vG)) + (kt) + (wt)); \
     (vH) += SIG0((vA)) + Sha512_Maj((vA),(vB),(vC)); } while (0)

    /* One step of SHA-512/256 computation with working variables rotation,
       see FIPS PUB 180-4 section 6.4.2 step 3. This macro version reassigns
       all working variables on each step. */
#define SHA2STEP64RV(vA,vB,vC,vD,vE,vF,vG,vH,kt,wt) do {                \
      curl_uint64_t tmp_h_ = (vH);                                      \
      SHA2STEP64((vA),(vB),(vC),(vD),(vE),(vF),(vG),tmp_h_,(kt),(wt));  \
      (vH) = (vG);                                                      \
      (vG) = (vF);                                                      \
      (vF) = (vE);                                                      \
      (vE) = (vD);                                                      \
      (vD) = (vC);                                                      \
      (vC) = (vB);                                                      \
      (vB) = (vA);                                                      \
      (vA) = tmp_h_;  } while(0)

    /* Get value of W(t) from input data buffer for 0 <= t <= 15,
       See FIPS PUB 180-4 section 6.2.
       Input data must be read in big-endian bytes order,
       see FIPS PUB 180-4 section 3.1.2. */
#define SHA512_GET_W_FROM_DATA(buf,t)                                   \
    CURL_GET_64BIT_BE(                                                  \
      ((const unsigned char*) (buf)) + (t) * SHA512_256_BYTES_IN_WORD)

    /* During first 16 steps, before making any calculation on each step, the
       W element is read from the input data buffer as a big-endian value and
       stored in the array of W elements. */
    for(t = 0; t < 16; ++t) {
      SHA2STEP64RV(a, b, c, d, e, f, g, h, K[t], \
                   W[t] = SHA512_GET_W_FROM_DATA(data, t));
    }

    /* 'W' generation and assignment for 16 <= t <= 79.
       See FIPS PUB 180-4 section 6.4.2.
       As only the last 16 'W' are used in calculations, it is possible to
       use 16 elements array of W as a cyclic buffer.
       Note: ((t-16) & 15) have same value as (t & 15) */
#define Wgen(w,t)                                                       \
    (curl_uint64_t)( (w)[(t - 16) & 15] + sig1((w)[((t) - 2) & 15])     \
                     + (w)[((t) - 7) & 15] + sig0((w)[((t) - 15) & 15]) )

    /* During the last 64 steps, before making any calculation on each step,
       current W element is generated from other W elements of the cyclic
       buffer and the generated value is stored back in the cyclic buffer. */
    for(t = 16; t < 80; ++t) {
      SHA2STEP64RV(a, b, c, d, e, f, g, h, K[t], \
                   W[t & 15] = Wgen(W, t));
    }
  }

  /* Compute and store the intermediate hash.
     See FIPS PUB 180-4 section 6.4.2 step 4. */
  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;
  H[5] += f;
  H[6] += g;
  H[7] += h;
}


/**
 * Process portion of bytes.
 *
 * @param context the calculation context
 * @param data bytes to add to hash
 * @param length number of bytes in @a data
 * @return always CURLE_OK
 */
static CURLcode
Curl_sha512_256_update(void *context,
                       const unsigned char *data,
                       size_t length)
{
  unsigned int bytes_have; /**< Number of bytes in the context buffer */
  struct Curl_sha512_256ctx *const ctx = (struct Curl_sha512_256ctx *)context;
  /* the void pointer here is required to mute Intel compiler warning */
  void *const ctx_buf = ctx->buffer;

  DEBUGASSERT((data != NULL) || (length == 0));

  if(0 == length)
    return CURLE_OK; /* Shortcut, do nothing */

  /* Note: (count & (CURL_SHA512_256_BLOCK_SIZE-1))
     equals (count % CURL_SHA512_256_BLOCK_SIZE) for this block size. */
  bytes_have = (unsigned int) (ctx->count & (CURL_SHA512_256_BLOCK_SIZE - 1));
  ctx->count += length;
  if(length > ctx->count)
    ctx->count_bits_hi += 1U << 3; /* Value wrap */
  ctx->count_bits_hi += ctx->count >> 61;
  ctx->count &= CURL_UINT64_C(0x1FFFFFFFFFFFFFFF);

  if(0 != bytes_have) {
    unsigned int bytes_left = CURL_SHA512_256_BLOCK_SIZE - bytes_have;
    if(length >= bytes_left) {
      /* Combine new data with data in the buffer and process the full
         block. */
      memcpy(((unsigned char *) ctx_buf) + bytes_have,
             data,
             bytes_left);
      data += bytes_left;
      length -= bytes_left;
      Curl_sha512_256_transform(ctx->H, ctx->buffer);
      bytes_have = 0;
    }
  }

  while(CURL_SHA512_256_BLOCK_SIZE <= length) {
    /* Process any full blocks of new data directly,
       without copying to the buffer. */
    Curl_sha512_256_transform(ctx->H, data);
    data += CURL_SHA512_256_BLOCK_SIZE;
    length -= CURL_SHA512_256_BLOCK_SIZE;
  }

  if(0 != length) {
    /* Copy incomplete block of new data (if any)
       to the buffer. */
    memcpy(((unsigned char *) ctx_buf) + bytes_have, data, length);
  }

  return CURLE_OK;
}



/**
 * Size of "length" insertion in bits.
 * See FIPS PUB 180-4 section 5.1.2.
 */
#define SHA512_256_SIZE_OF_LEN_ADD_BITS 128

/**
 * Size of "length" insertion in bytes.
 */
#define SHA512_256_SIZE_OF_LEN_ADD (SHA512_256_SIZE_OF_LEN_ADD_BITS / 8)

/**
 * Finalise SHA-512/256 calculation, return digest.
 *
 * @param context the calculation context
 * @param[out] digest set to the hash, must be #CURL_SHA512_256_DIGEST_SIZE
 #             bytes
 * @return always CURLE_OK
 */
static CURLcode
Curl_sha512_256_finish(unsigned char *digest,
                       void *context)
{
  struct Curl_sha512_256ctx *const ctx = (struct Curl_sha512_256ctx *)context;
  curl_uint64_t num_bits;   /**< Number of processed bits */
  unsigned int bytes_have; /**< Number of bytes in the context buffer */
  /* the void pointer here is required to mute Intel compiler warning */
  void *const ctx_buf = ctx->buffer;

  /* Memorise the number of processed bits.
     The padding and other data added here during the postprocessing must
     not change the amount of hashed data. */
  num_bits = ctx->count << 3;

  /* Note: (count & (CURL_SHA512_256_BLOCK_SIZE-1))
           equals (count % CURL_SHA512_256_BLOCK_SIZE) for this block size. */
  bytes_have = (unsigned int) (ctx->count & (CURL_SHA512_256_BLOCK_SIZE - 1));

  /* Input data must be padded with a single bit "1", then with zeros and
     the finally the length of data in bits must be added as the final bytes
     of the last block.
     See FIPS PUB 180-4 section 5.1.2. */

  /* Data is always processed in form of bytes (not by individual bits),
     therefore position of the first padding bit in byte is always
     predefined (0x80). */
  /* Buffer always have space at least for one byte (as full buffers are
     processed when formed). */
  ((unsigned char *) ctx_buf)[bytes_have++] = 0x80U;

  if(CURL_SHA512_256_BLOCK_SIZE - bytes_have < SHA512_256_SIZE_OF_LEN_ADD) {
    /* No space in the current block to put the total length of message.
       Pad the current block with zeros and process it. */
    if(bytes_have < CURL_SHA512_256_BLOCK_SIZE)
      memset(((unsigned char *) ctx_buf) + bytes_have, 0,
             CURL_SHA512_256_BLOCK_SIZE - bytes_have);
    /* Process the full block. */
    Curl_sha512_256_transform(ctx->H, ctx->buffer);
    /* Start the new block. */
    bytes_have = 0;
  }

  /* Pad the rest of the buffer with zeros. */
  memset(((unsigned char *) ctx_buf) + bytes_have, 0,
         CURL_SHA512_256_BLOCK_SIZE - SHA512_256_SIZE_OF_LEN_ADD - bytes_have);
  /* Put high part of number of bits in processed message and then lower
     part of number of bits as big-endian values.
     See FIPS PUB 180-4 section 5.1.2. */
  /* Note: the target location is predefined and buffer is always aligned */
  CURL_PUT_64BIT_BE(((unsigned char *) ctx_buf)  \
                      + CURL_SHA512_256_BLOCK_SIZE    \
                      - SHA512_256_SIZE_OF_LEN_ADD,   \
                      ctx->count_bits_hi);
  CURL_PUT_64BIT_BE(((unsigned char *) ctx_buf)      \
                      + CURL_SHA512_256_BLOCK_SIZE        \
                      - SHA512_256_SIZE_OF_LEN_ADD        \
                      + SHA512_256_BYTES_IN_WORD,         \
                      num_bits);
  /* Process the full final block. */
  Curl_sha512_256_transform(ctx->H, ctx->buffer);

  /* Put in BE mode the leftmost part of the hash as the final digest.
     See FIPS PUB 180-4 section 6.7. */

  CURL_PUT_64BIT_BE((digest + 0 * SHA512_256_BYTES_IN_WORD), ctx->H[0]);
  CURL_PUT_64BIT_BE((digest + 1 * SHA512_256_BYTES_IN_WORD), ctx->H[1]);
  CURL_PUT_64BIT_BE((digest + 2 * SHA512_256_BYTES_IN_WORD), ctx->H[2]);
  CURL_PUT_64BIT_BE((digest + 3 * SHA512_256_BYTES_IN_WORD), ctx->H[3]);

  /* Erase potentially sensitive data. */
  memset(ctx, 0, sizeof(struct Curl_sha512_256ctx));

  return CURLE_OK;
}

#endif /* Local SHA-512/256 code */


/**
 * Compute SHA-512/256 hash for the given data in one function call
 * @param[out] output the pointer to put the hash
 * @param[in] input the pointer to the data to process
 * @param input_size the size of the data pointed by @a input
 * @return always #CURLE_OK
 */
CURLcode
Curl_sha512_256it(unsigned char *output, const unsigned char *input,
                  size_t input_size)
{
  Curl_sha512_256_ctx ctx;
  CURLcode res;

  res = Curl_sha512_256_init(&ctx);
  if(res != CURLE_OK)
    return res;

  res = Curl_sha512_256_update(&ctx, (const void *) input, input_size);

  if(res != CURLE_OK) {
    (void) Curl_sha512_256_finish(output, &ctx);
    return res;
  }

  return Curl_sha512_256_finish(output, &ctx);
}

/* Wrapper function, takes 'unsigned int' as length type, returns void */
static void
Curl_sha512_256_update_i(void *context,
                         const unsigned char *data,
                         unsigned int length)
{
  /* Hypothetically the function may fail, but assume it does not */
  (void) Curl_sha512_256_update(context, data, length);
}

/* Wrapper function, returns void */
static void
Curl_sha512_256_finish_v(unsigned char *result,
                         void *context)
{
  /* Hypothetically the function may fail, but assume it does not */
  (void) Curl_sha512_256_finish(result, context);
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

#endif /* !CURL_DISABLE_DIGEST_AUTH && !CURL_DISABLE_SHA512_256 */
