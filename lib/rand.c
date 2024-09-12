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

#include <limits.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "vtls/vtls.h"
#include "sendf.h"
#include "timeval.h"
#include "rand.h"
#include "escape.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifdef _WIN32

#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x600 && \
  !defined(CURL_WINDOWS_APP)
#  define HAVE_WIN_BCRYPTGENRANDOM
#  include <bcrypt.h>
#  ifdef _MSC_VER
#    pragma comment(lib, "bcrypt.lib")
#  endif
#  ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#  define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#  endif
#  ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#  endif
#elif defined(USE_WIN32_CRYPTO)
#  include <wincrypt.h>
#  ifdef _MSC_VER
#    pragma comment(lib, "advapi32.lib")
#  endif
#endif

CURLcode Curl_win32_random(unsigned char *entropy, size_t length)
{
  memset(entropy, 0, length);

#if defined(HAVE_WIN_BCRYPTGENRANDOM)
  if(BCryptGenRandom(NULL, entropy, (ULONG)length,
                     BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    return CURLE_FAILED_INIT;

  return CURLE_OK;
#elif defined(USE_WIN32_CRYPTO)
  {
    HCRYPTPROV hCryptProv = 0;

    if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
      return CURLE_FAILED_INIT;

    if(!CryptGenRandom(hCryptProv, (DWORD)length, entropy)) {
      CryptReleaseContext(hCryptProv, 0UL);
      return CURLE_FAILED_INIT;
    }

    CryptReleaseContext(hCryptProv, 0UL);
  }
  return CURLE_OK;
#else
  return CURLE_NOT_BUILT_IN;
#endif
}
#endif

#if !defined(USE_SSL)
/* ---- possibly non-cryptographic version following ---- */
static CURLcode weak_random(struct Curl_easy *data,
                          unsigned char *entropy,
                          size_t length) /* always 4, size of int */
{
  unsigned int r;
  DEBUGASSERT(length == sizeof(int));

  /* Trying cryptographically secure functions first */
#ifdef _WIN32
  (void)data;
  {
    CURLcode result = Curl_win32_random(entropy, length);
    if(result != CURLE_NOT_BUILT_IN)
      return result;
  }
#endif

#if defined(HAVE_ARC4RANDOM)
  (void)data;
  r = (unsigned int)arc4random();
  memcpy(entropy, &r, length);
#else
  infof(data, "WARNING: using weak random seed");
  {
    static unsigned int randseed;
    static bool seeded = FALSE;
    unsigned int rnd;
    if(!seeded) {
      struct curltime now = Curl_now();
      randseed += (unsigned int)now.tv_usec + (unsigned int)now.tv_sec;
      randseed = randseed * 1103515245 + 12345;
      randseed = randseed * 1103515245 + 12345;
      randseed = randseed * 1103515245 + 12345;
      seeded = TRUE;
    }

    /* Return an unsigned 32-bit pseudo-random number. */
    r = randseed = randseed * 1103515245 + 12345;
    rnd = (r << 16) | ((r >> 16) & 0xFFFF);
    memcpy(entropy, &rnd, length);
  }
#endif
  return CURLE_OK;
}
#endif

#ifdef USE_SSL
#define _random(x,y,z) Curl_ssl_random(x,y,z)
#else
#define _random(x,y,z) weak_random(x,y,z)
#endif

static CURLcode randit(struct Curl_easy *data, unsigned int *rnd,
                       bool env_override)
{
#ifdef DEBUGBUILD
  if(env_override) {
    char *force_entropy = getenv("CURL_ENTROPY");
    if(force_entropy) {
      static unsigned int randseed;
      static bool seeded = FALSE;

      if(!seeded) {
        unsigned int seed = 0;
        size_t elen = strlen(force_entropy);
        size_t clen = sizeof(seed);
        size_t min = elen < clen ? elen : clen;
        memcpy((char *)&seed, force_entropy, min);
        randseed = ntohl(seed);
        seeded = TRUE;
      }
      else
        randseed++;
      *rnd = randseed;
      return CURLE_OK;
    }
  }
#else
  (void)env_override;
#endif

  /* data may be NULL! */
  return _random(data, (unsigned char *)rnd, sizeof(*rnd));
}

/*
 * Curl_rand() stores 'num' number of random unsigned characters in the buffer
 * 'rnd' points to.
 *
 * If libcurl is built without TLS support or with a TLS backend that lacks a
 * proper random API (Rustls or mbedTLS), this function will use "weak"
 * random.
 *
 * When built *with* TLS support and a backend that offers strong random, it
 * will return error if it cannot provide strong random values.
 *
 * NOTE: 'data' may be passed in as NULL when coming from external API without
 * easy handle!
 *
 */

CURLcode Curl_rand_bytes(struct Curl_easy *data,
#ifdef DEBUGBUILD
                         bool env_override,
#endif
                         unsigned char *rnd, size_t num)
{
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
#ifndef DEBUGBUILD
  const bool env_override = FALSE;
#endif

  DEBUGASSERT(num);

  while(num) {
    unsigned int r;
    size_t left = num < sizeof(unsigned int) ? num : sizeof(unsigned int);

    result = randit(data, &r, env_override);
    if(result)
      return result;

    while(left) {
      *rnd++ = (unsigned char)(r & 0xFF);
      r >>= 8;
      --num;
      --left;
    }
  }

  return result;
}

/*
 * Curl_rand_hex() fills the 'rnd' buffer with a given 'num' size with random
 * hexadecimal digits PLUS a null-terminating byte. It must be an odd number
 * size.
 */

CURLcode Curl_rand_hex(struct Curl_easy *data, unsigned char *rnd,
                       size_t num)
{
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  unsigned char buffer[128];
  DEBUGASSERT(num > 1);

#ifdef __clang_analyzer__
  /* This silences a scan-build warning about accessing this buffer with
     uninitialized memory. */
  memset(buffer, 0, sizeof(buffer));
#endif

  if((num/2 >= sizeof(buffer)) || !(num&1)) {
    /* make sure it fits in the local buffer and that it is an odd number! */
    DEBUGF(infof(data, "invalid buffer size with Curl_rand_hex"));
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  num--; /* save one for null-termination */

  result = Curl_rand(data, buffer, num/2);
  if(result)
    return result;

  Curl_hexencode(buffer, num/2, rnd, num + 1);
  return result;
}

/*
 * Curl_rand_alnum() fills the 'rnd' buffer with a given 'num' size with random
 * alphanumerical chars PLUS a null-terminating byte.
 */

static const char alnum[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

CURLcode Curl_rand_alnum(struct Curl_easy *data, unsigned char *rnd,
                         size_t num)
{
  CURLcode result = CURLE_OK;
  const unsigned int alnumspace = sizeof(alnum) - 1;
  unsigned int r;
  DEBUGASSERT(num > 1);

  num--; /* save one for null-termination */

  while(num) {
    do {
      result = randit(data, &r, TRUE);
      if(result)
        return result;
    } while(r >= (UINT_MAX - UINT_MAX % alnumspace));

    *rnd++ = (unsigned char)alnum[r % alnumspace];
    num--;
  }
  *rnd = 0;

  return result;
}
