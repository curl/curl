/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <curl/curl.h>
#include "vtls/vtls.h"
#include "sendf.h"
#include "rand.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static CURLcode randit(struct Curl_easy *data, unsigned int *rnd)
{
  unsigned int r;
  CURLcode result = CURLE_OK;
  static unsigned int randseed;
  static bool seeded = FALSE;

#ifdef CURLDEBUG
  char *force_entropy = getenv("CURL_ENTROPY");
  if(force_entropy) {
    if(!seeded) {
      size_t elen = strlen(force_entropy);
      size_t clen = sizeof(randseed);
      size_t min = elen < clen ? elen : clen;
      memcpy((char *)&randseed, force_entropy, min);
      seeded = TRUE;
    }
    else
      randseed++;
    *rnd = randseed;
    return CURLE_OK;
  }
#endif

  /* data may be NULL! */
  result = Curl_ssl_random(data, (unsigned char *)rnd, sizeof(*rnd));
  if(result != CURLE_NOT_BUILT_IN)
    /* only if there is no random funtion in the TLS backend do the non crypto
       version, otherwise return result */
    return result;

  /* ---- non-cryptographic version following ---- */

#ifdef RANDOM_FILE
  if(!seeded) {
    /* if there's a random file to read a seed from, use it */
    int fd = open(RANDOM_FILE, O_RDONLY);
    if(fd > -1) {
      /* read random data into the randseed variable */
      ssize_t nread = read(fd, &randseed, sizeof(randseed));
      if(nread == sizeof(randseed))
        seeded = TRUE;
      close(fd);
    }
  }
#endif

  if(!seeded) {
    struct timeval now = curlx_tvnow();
    infof(data, "WARNING: Using weak random seed\n");
    randseed += (unsigned int)now.tv_usec + (unsigned int)now.tv_sec;
    randseed = randseed * 1103515245 + 12345;
    randseed = randseed * 1103515245 + 12345;
    randseed = randseed * 1103515245 + 12345;
    seeded = TRUE;
  }

  /* Return an unsigned 32-bit pseudo-random number. */
  r = randseed = randseed * 1103515245 + 12345;
  *rnd = (r << 16) | ((r >> 16) & 0xFFFF);
  return CURLE_OK;
}

/*
 * Curl_rand() stores 'num' number of random unsigned integers in the buffer
 * 'rndptr' points to.
 *
 * If libcurl is built without TLS support or with a TLS backend that lacks a
 * proper random API (Gskit, PolarSSL or mbedTLS), this function will use
 * "weak" random.
 *
 * When built *with* TLS support and a backend that offers strong random, it
 * will return error if it cannot provide strong random values.
 *
 * NOTE: 'data' may be passed in as NULL when coming from external API without
 * easy handle!
 *
 */

CURLcode Curl_rand(struct Curl_easy *data, unsigned int *rndptr,
                   unsigned int num)
{
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  unsigned int i;

  assert(num > 0);

  for(i = 0; i < num; i++) {
    result = randit(data, rndptr++);
    if(result)
      return result;
  }
  return result;
}
