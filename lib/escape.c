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
      target[1] = Curl_udigits[in >> 4];
      target[2] = Curl_udigits[in & 0x0F];
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
