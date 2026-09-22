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
/* Escape and unescape URL encoding in strings. The functions return a new
 * allocated string or NULL if an error occurred. */
#include "curl_setup.h"

struct Curl_easy;

#include "urldata.h"
#include "escape.h"
#include "curlx/strparse.h"
#include "curl_printf.h"

#if defined(__x86_64__) && !defined(__INTEL_COMPILER) && \
  ((defined(__GNUC__) && __GNUC__ >= 9) || \
   (defined(__clang__) && __clang_major__ >= 10))
#include <immintrin.h>
#define URLDECODE_VBMI2 1
#endif

/* for ABI-compatibility with previous versions */
char *curl_escape(const char *string, int length)
{
  return curl_easy_escape(NULL, string, length);
}

/* for ABI-compatibility with previous versions */
char *curl_unescape(const char *string, int length)
{
  return curl_easy_unescape(NULL, string, length, NULL);
}

#define NOPE 0xff
#define _OK_ 0x1f /* octet not needing encoding but not a hexadecimal
                     character */

static const unsigned char hextable[256] = {
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 00 */
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 08 */
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 10 */
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 18 */
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 20 */
  NOPE, NOPE, NOPE, NOPE, NOPE, _OK_, _OK_, NOPE, /* 28 */
  0,    1,    2,    3,    4,    5,    6,    7,    /* 30 */
  8,    9,    NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 38 */
  NOPE, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, _OK_, /* 40 */
  _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, /* 48 */
  _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, /* 50 */
  _OK_, _OK_, _OK_, NOPE, NOPE, NOPE, NOPE, _OK_, /* 58 */
  NOPE, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, _OK_, /* 60 */
  _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, /* 68 */
  _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, _OK_, /* 70 */
  _OK_, _OK_, _OK_, NOPE, NOPE, NOPE, _OK_, NOPE, /* 78 */
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, /* 80 - not ASCII */
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE,
  NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE, NOPE
};

static const char hexpairs[][2] = {
  {'0', '0'}, {'0', '1'}, {'0', '2'}, {'0', '3'},
  {'0', '4'}, {'0', '5'}, {'0', '6'}, {'0', '7'},
  {'0', '8'}, {'0', '9'}, {'0', 'A'}, {'0', 'B'},
  {'0', 'C'}, {'0', 'D'}, {'0', 'E'}, {'0', 'F'},
  {'1', '0'}, {'1', '1'}, {'1', '2'}, {'1', '3'},
  {'1', '4'}, {'1', '5'}, {'1', '6'}, {'1', '7'},
  {'1', '8'}, {'1', '9'}, {'1', 'A'}, {'1', 'B'},
  {'1', 'C'}, {'1', 'D'}, {'1', 'E'}, {'1', 'F'},
  {'2', '0'}, {'2', '1'}, {'2', '2'}, {'2', '3'},
  {'2', '4'}, {'2', '5'}, {'2', '6'}, {'2', '7'},
  {'2', '8'}, {'2', '9'}, {'2', 'A'}, {'2', 'B'},
  {'2', 'C'}, {'2', 'D'}, {'2', 'E'}, {'2', 'F'},
  {'3', '0'}, {'3', '1'}, {'3', '2'}, {'3', '3'},
  {'3', '4'}, {'3', '5'}, {'3', '6'}, {'3', '7'},
  {'3', '8'}, {'3', '9'}, {'3', 'A'}, {'3', 'B'},
  {'3', 'C'}, {'3', 'D'}, {'3', 'E'}, {'3', 'F'},
  {'4', '0'}, {'4', '1'}, {'4', '2'}, {'4', '3'},
  {'4', '4'}, {'4', '5'}, {'4', '6'}, {'4', '7'},
  {'4', '8'}, {'4', '9'}, {'4', 'A'}, {'4', 'B'},
  {'4', 'C'}, {'4', 'D'}, {'4', 'E'}, {'4', 'F'},
  {'5', '0'}, {'5', '1'}, {'5', '2'}, {'5', '3'},
  {'5', '4'}, {'5', '5'}, {'5', '6'}, {'5', '7'},
  {'5', '8'}, {'5', '9'}, {'5', 'A'}, {'5', 'B'},
  {'5', 'C'}, {'5', 'D'}, {'5', 'E'}, {'5', 'F'},
  {'6', '0'}, {'6', '1'}, {'6', '2'}, {'6', '3'},
  {'6', '4'}, {'6', '5'}, {'6', '6'}, {'6', '7'},
  {'6', '8'}, {'6', '9'}, {'6', 'A'}, {'6', 'B'},
  {'6', 'C'}, {'6', 'D'}, {'6', 'E'}, {'6', 'F'},
  {'7', '0'}, {'7', '1'}, {'7', '2'}, {'7', '3'},
  {'7', '4'}, {'7', '5'}, {'7', '6'}, {'7', '7'},
  {'7', '8'}, {'7', '9'}, {'7', 'A'}, {'7', 'B'},
  {'7', 'C'}, {'7', 'D'}, {'7', 'E'}, {'7', 'F'},
  {'8', '0'}, {'8', '1'}, {'8', '2'}, {'8', '3'},
  {'8', '4'}, {'8', '5'}, {'8', '6'}, {'8', '7'},
  {'8', '8'}, {'8', '9'}, {'8', 'A'}, {'8', 'B'},
  {'8', 'C'}, {'8', 'D'}, {'8', 'E'}, {'8', 'F'},
  {'9', '0'}, {'9', '1'}, {'9', '2'}, {'9', '3'},
  {'9', '4'}, {'9', '5'}, {'9', '6'}, {'9', '7'},
  {'9', '8'}, {'9', '9'}, {'9', 'A'}, {'9', 'B'},
  {'9', 'C'}, {'9', 'D'}, {'9', 'E'}, {'9', 'F'},
  {'A', '0'}, {'A', '1'}, {'A', '2'}, {'A', '3'},
  {'A', '4'}, {'A', '5'}, {'A', '6'}, {'A', '7'},
  {'A', '8'}, {'A', '9'}, {'A', 'A'}, {'A', 'B'},
  {'A', 'C'}, {'A', 'D'}, {'A', 'E'}, {'A', 'F'},
  {'B', '0'}, {'B', '1'}, {'B', '2'}, {'B', '3'},
  {'B', '4'}, {'B', '5'}, {'B', '6'}, {'B', '7'},
  {'B', '8'}, {'B', '9'}, {'B', 'A'}, {'B', 'B'},
  {'B', 'C'}, {'B', 'D'}, {'B', 'E'}, {'B', 'F'},
  {'C', '0'}, {'C', '1'}, {'C', '2'}, {'C', '3'},
  {'C', '4'}, {'C', '5'}, {'C', '6'}, {'C', '7'},
  {'C', '8'}, {'C', '9'}, {'C', 'A'}, {'C', 'B'},
  {'C', 'C'}, {'C', 'D'}, {'C', 'E'}, {'C', 'F'},
  {'D', '0'}, {'D', '1'}, {'D', '2'}, {'D', '3'},
  {'D', '4'}, {'D', '5'}, {'D', '6'}, {'D', '7'},
  {'D', '8'}, {'D', '9'}, {'D', 'A'}, {'D', 'B'},
  {'D', 'C'}, {'D', 'D'}, {'D', 'E'}, {'D', 'F'},
  {'E', '0'}, {'E', '1'}, {'E', '2'}, {'E', '3'},
  {'E', '4'}, {'E', '5'}, {'E', '6'}, {'E', '7'},
  {'E', '8'}, {'E', '9'}, {'E', 'A'}, {'E', 'B'},
  {'E', 'C'}, {'E', 'D'}, {'E', 'E'}, {'E', 'F'},
  {'F', '0'}, {'F', '1'}, {'F', '2'}, {'F', '3'},
  {'F', '4'}, {'F', '5'}, {'F', '6'}, {'F', '7'},
  {'F', '8'}, {'F', '9'}, {'F', 'A'}, {'F', 'B'},
  {'F', 'C'}, {'F', 'D'}, {'F', 'E'}, {'F', 'F'}
};

/* Escapes for URL the given unescaped string of given length.
 * 'data' is ignored since 7.82.0.
 */
char *curl_easy_escape(CURL *curl, const char *string, int length)
{
  size_t len;
  const char *f = string;
  size_t nappend = 0;
  char *target;
  char *encoded;
  (void)curl;

  if(!string || (length < 0))
    return NULL;

  len = (length ? (size_t)length : strlen(string));
  if(!len)
    return curlx_strdup("");

  if(len > SIZE_MAX / 16)
    return NULL;

  encoded = target = curlx_malloc((len * 3) + 1);
  if(!target)
    return NULL;

  while(len--) {
    uint8_t in = (uint8_t)*string++;

    if(!(hextable[in] & 0x80))
      /* append this */
      nappend++;
    else {
      if(nappend) {
        memcpy(target, f, nappend);
        target += nappend;
        nappend = 0;
      }
      f = string;
      /* encode it */
      target[0] = '%';
      memcpy(target + 1, hexpairs[in], 2);
      target += 3;
    }
  }
  if(nappend) {
    memcpy(target, f, nappend);
    target += nappend;
  }
  *target = '\0'; /* null terminate */

  return encoded;
}

/*
 * Curl_urldecode() URL decodes the given string.
 *
 * Returns a pointer to a malloced string in *ostring with length given in
 * *olen. If length == 0, the length is assumed to be strlen(string).
 *
 * ctrl options:
 * - REJECT_NADA: accept everything
 * - REJECT_CTRL: rejects control characters (byte codes lower than 32) in
 *                the data
 * - REJECT_ZERO: rejects decoded zero bytes
 *
 * The values for the enum starts at 2, to make the assert detect legacy
 * invokes that used TRUE/FALSE (0 and 1).
 */

#ifdef URLDECODE_VBMI2
/* Load unaligned bytes without casting the input to a vector pointer. */
__attribute__((target("avx2")))
static __m256i urldecode_load(const char *string)
{
  __m256i src;
  memcpy(&src, string, sizeof(src));
  return src;
}

/* Valid escapes cannot overlap: '%' is not a hex digit. Treat decoding as
   vector substitution followed by a filter dropping the two hex lanes. */
__attribute__((target("avx512vbmi2,avx512vl,avx512bw,avx2,popcnt")))
static int urldecode_vbmi2(const char **input, size_t *remaining,
                          char **output, unsigned char reject_limit)
{
  const char *string = *input;
  size_t alloc = *remaining;
  char *ns = *output;

  while(alloc >= 32) {
    __m256i src = urldecode_load(string);
    unsigned int percent = (unsigned int)_mm256_cmpeq_epi8_mask(
      src, _mm256_set1_epi8('%'));
    if(!percent) {
      /* Only use libc after proving a 128-byte literal prefix.
         A percent in the next vector avoids probing farther ahead. */
      if(alloc >= 128 && !_mm256_cmpeq_epi8_mask(
           urldecode_load(string + 32),
           _mm256_set1_epi8('%')) &&
         !(_mm256_cmpeq_epi8_mask(
             urldecode_load(string + 64),
             _mm256_set1_epi8('%')) |
           _mm256_cmpeq_epi8_mask(
             urldecode_load(string + 96),
             _mm256_set1_epi8('%')))) {
        const char *p = memchr(string + 128, '%', alloc - 128);
        size_t n = p ? (size_t)(p - string) : alloc;
        if(reject_limit) {
          if(reject_limit == 1) {
            if(memchr(string, 0, n))
              return 0;
          }
          else {
            size_t i;
            for(i = 0; i < n; i++) {
              if((uint8_t)string[i] < 0x20)
                return 0;
            }
          }
        }
        memcpy(ns, string, n);
        ns += n;
        string += n;
        alloc -= n;
        continue;
      }
      if(reject_limit && _mm256_cmp_epu8_mask(
           src, _mm256_set1_epi8((char)reject_limit), _MM_CMPINT_LT))
        return 0;
      memcpy(ns, &src, sizeof(src));
      ns += 32;
      string += 32;
      alloc -= 32;
    }
    else {
      __m256i digit = _mm256_sub_epi8(src, _mm256_set1_epi8('0'));
      __m256i letter = _mm256_sub_epi8(
        _mm256_or_si256(src, _mm256_set1_epi8(32)),
        _mm256_set1_epi8('a'));
      __mmask32 digit_ok = _mm256_cmp_epu8_mask(
        digit, _mm256_set1_epi8(9), _MM_CMPINT_LE);
      __mmask32 letter_ok = _mm256_cmp_epu8_mask(
        letter, _mm256_set1_epi8(5), _MM_CMPINT_LE);
      unsigned int hex = (unsigned int)(digit_ok | letter_ok);
      unsigned int escapes = percent & (hex >> 1) & (hex >> 2);
      unsigned int consumed = (percent & (1U << 30)) ? 30 :
        (percent & (1U << 31)) ? 31 : 32;
      unsigned int keep = (0xffffffffU >> (32 - consumed)) &
        ~((escapes << 1) | (escapes << 2));
      __m256i low = _mm256_and_si256(src, _mm256_set1_epi8(15));
      __m256i nibble = _mm256_mask_add_epi8(
        low, letter_ok, low, _mm256_set1_epi8(9));
      /* AVX2 byte shifts are lane-local. Bring the upper half into the
         lower half, zero the upper half, then align across the boundary. */
      __m256i upper = _mm256_permute2x128_si256(nibble, nibble, 0x81);
      __m256i high_nibble = _mm256_alignr_epi8(upper, nibble, 1);
      __m256i low_nibble = _mm256_alignr_epi8(upper, nibble, 2);
      __m256i decoded = _mm256_or_si256(
        _mm256_and_si256(_mm256_slli_epi16(high_nibble, 4),
                          _mm256_set1_epi8((char)0xf0)),
        low_nibble);
      __m256i result = _mm256_mask_mov_epi8(src, (__mmask32)escapes,
                                           decoded);
      if(reject_limit && ((unsigned int)_mm256_cmp_epu8_mask(
           result, _mm256_set1_epi8((char)reject_limit), _MM_CMPINT_LT) &
                          keep))
        return 0;
      /* Register compression plus an ordinary store avoids the masked
         memory form. The store may write temporary padding, but at least
         32 input bytes remain and output never exceeds input, so all 32
         stored bytes fit the original allocation. The next iteration or
         final terminator replaces padding within the logical output. */
      result = _mm256_maskz_compress_epi8((__mmask32)keep, result);
      memcpy(ns, &result, sizeof(result));
      ns += (unsigned int)__builtin_popcount(keep);
      string += consumed;
      alloc -= consumed;
    }
  }
  *input = string;
  *remaining = alloc;
  *output = ns;
  return 1;
}
#endif

CURLcode Curl_urldecode(const char *string, size_t length,
                        char **ostring, size_t *olen,
                        enum urlreject ctrl)
{
  size_t alloc;
  char *ns;
  uint8_t reject_limit;

  DEBUGASSERT(string);
  DEBUGASSERT(ctrl >= REJECT_NADA); /* crash on TRUE/FALSE */

  alloc = (length ? length : strlen(string));
  ns = curlx_malloc(alloc + 1);

  if(!ns)
    return CURLE_OUT_OF_MEMORY;

  /* store output string */
  *ostring = ns;

  reject_limit = (ctrl == REJECT_CTRL) ? 0x20 :
    (ctrl == REJECT_ZERO) ? 1 : 0;

#ifdef URLDECODE_VBMI2
  if(alloc >= 32 &&
     __builtin_cpu_supports("avx512vbmi2") &&
     __builtin_cpu_supports("avx512vl") &&
     __builtin_cpu_supports("avx512bw") &&
     __builtin_cpu_supports("avx2") &&
     __builtin_cpu_supports("popcnt")) {
    if(!urldecode_vbmi2(&string, &alloc, &ns, reject_limit))
      goto error;
  }
#endif

  while(alloc) {
    uint8_t in;

    if(*string == '%') {
      if(alloc > 2) {
        uint8_t h1 = hextable[(uint8_t)string[1]];
        uint8_t h2 = hextable[(uint8_t)string[2]];
        if(!((h1 | h2) & 0xf0)) {
          in = (uint8_t)((h1 << 4) | h2);
          string += 3;
          alloc -= 3;
          if(in < reject_limit)
            goto error;
          *ns++ = (char)in;
          continue;
        }
      }
      in = '%';
      string++;
      alloc--;
      *ns++ = (char)in;
      continue;
    }
    else {
      const char *p = memchr(string + 1, '%', alloc - 1);
      size_t n = p ? (size_t)(p - string) : alloc;

      if(reject_limit) {
        if(reject_limit == 1) {
          if(memchr(string, 0, n))
            goto error;
        }
        else {
          size_t i;
          for(i = 0; i < n; i++) {
            if((uint8_t)string[i] < 0x20)
              goto error;
          }
        }
      }

      memcpy(ns, string, n);
      ns += n;
      string += n;
      alloc -= n;
    }
  }
  *ns = 0; /* terminate it */

  if(olen)
    /* store output size */
    *olen = (size_t)(ns - *ostring);

  return CURLE_OK;
error:
  curlx_safefree(*ostring);
  return CURLE_URL_MALFORMAT;
}

/*
 * Unescapes the given URL escaped string of given length. Returns a
 * pointer to a malloced string with length given in *olen.
 * If length == 0, the length is assumed to be strlen(string).
 * If olen == NULL, no output length is stored.
 * 'data' is ignored since 7.82.0.
 */
char *curl_easy_unescape(CURL *curl, const char *string, int inlength,
                         int *outlength)
{
  char *str = NULL;
  (void)curl;
  if(string && (inlength >= 0)) {
    size_t inputlen = (size_t)inlength;
    size_t outputlen;
    CURLcode res = Curl_urldecode(string, inputlen, &str, &outputlen,
                                  REJECT_NADA);
    if(res)
      return NULL;

    if(outlength) {
      if(outputlen <= (size_t)INT_MAX)
        *outlength = curlx_uztosi(outputlen);
      else
        /* too large to return in an int, fail! */
        curlx_safefree(str);
    }
  }
  return str;
}

/* For operating systems/environments that use different malloc/free
   systems for the app and for this library, we provide a free that uses
   the library's memory system */
void curl_free(void *p)
{
  curlx_free(p);
}

/*
 * Curl_hexencode()
 *
 * Converts binary input to lowercase hex-encoded ASCII output.
 * null-terminated.
 */
void Curl_hexencode(const unsigned char *src, size_t len, /* input length */
                    unsigned char *out, size_t olen) /* output buffer size */
{
  DEBUGASSERT(src && len && (olen >= 3));
  if(src && len && (olen >= 3)) {
    while(len-- && (olen >= 3)) {
      out[0] = Curl_ldigits[*src >> 4];
      out[1] = Curl_ldigits[*src & 0x0F];
      ++src;
      out += 2;
      olen -= 2;
    }
    *out = 0;
  }
  else if(olen)
    *out = 0;
}

/* Curl_hexbyte
 *
 * Output a single unsigned char as a two-digit UPPERCASE hex number.
 */
void Curl_hexbyte(unsigned char *dest, /* must fit two bytes */
                  unsigned char val)
{
  dest[0] = Curl_udigits[val >> 4];
  dest[1] = Curl_udigits[val & 0x0F];
}
