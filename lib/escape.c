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
 * allocated string or NULL if an error occurred.  */

#include "curl_setup.h"

#include <curl/curl.h>

struct Curl_easy;

#include "urldata.h"
#include "warnless.h"
#include "escape.h"
#include "strdup.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* for ABI-compatibility with previous versions */
char *curl_escape(const char *string, int inlength)
{
  return curl_easy_escape(NULL, string, inlength);
}

/* for ABI-compatibility with previous versions */
char *curl_unescape(const char *string, int length)
{
  return curl_easy_unescape(NULL, string, length, NULL);
}

/* Escapes for URL the given unescaped string of given length.
 * 'data' is ignored since 7.82.0.
 */
char *curl_easy_escape(CURL *data, const char *string,
                       int inlength)
{
  size_t length;
  struct dynbuf d;
  (void)data;

  if(!string || (inlength < 0))
    return NULL;

  length = (inlength ? (size_t)inlength : strlen(string));
  if(!length)
    return strdup("");

  Curl_dyn_init(&d, length * 3 + 1);

  while(length--) {
    /* treat the characters unsigned */
    unsigned char in = (unsigned char)*string++;

    if(ISUNRESERVED(in)) {
      /* append this */
      if(Curl_dyn_addn(&d, &in, 1))
        return NULL;
    }
    else {
      /* encode it */
      const char hex[] = "0123456789ABCDEF";
      char out[3]={'%'};
      out[1] = hex[in >> 4];
      out[2] = hex[in & 0xf];
      if(Curl_dyn_addn(&d, out, 3))
        return NULL;
    }
  }

  return Curl_dyn_ptr(&d);
}

static const unsigned char hextable[] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,       /* 0x30 - 0x3f */
  0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40 - 0x4f */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,       /* 0x50 - 0x5f */
  0, 10, 11, 12, 13, 14, 15                             /* 0x60 - 0x66 */
};

/* the input is a single hex digit */
#define onehex2dec(x) hextable[x - '0']

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

  DEBUGASSERT(string);
  DEBUGASSERT(ctrl >= REJECT_NADA); /* crash on TRUE/FALSE */

  alloc = (length ? length : strlen(string));
  ns = malloc(alloc + 1);

  if(!ns)
    return CURLE_OUT_OF_MEMORY;

  /* store output string */
  *ostring = ns;

  while(alloc) {
    unsigned char in = (unsigned char)*string;
    if(('%' == in) && (alloc > 2) &&
       ISXDIGIT(string[1]) && ISXDIGIT(string[2])) {
      /* this is two hexadecimal digits following a '%' */
      in = (unsigned char)(onehex2dec(string[1]) << 4) | onehex2dec(string[2]);

      string += 3;
      alloc -= 3;
    }
    else {
      string++;
      alloc--;
    }

    if(((ctrl == REJECT_CTRL) && (in < 0x20)) ||
       ((ctrl == REJECT_ZERO) && (in == 0))) {
      Curl_safefree(*ostring);
      return CURLE_URL_MALFORMAT;
    }

    *ns++ = (char)in;
  }
  *ns = 0; /* terminate it */

  if(olen)
    /* store output size */
    *olen = ns - *ostring;

  return CURLE_OK;
}

/*
 * Unescapes the given URL escaped string of given length. Returns a
 * pointer to a malloced string with length given in *olen.
 * If length == 0, the length is assumed to be strlen(string).
 * If olen == NULL, no output length is stored.
 * 'data' is ignored since 7.82.0.
 */
char *curl_easy_unescape(CURL *data, const char *string,
                         int length, int *olen)
{
  char *str = NULL;
  (void)data;
  if(string && (length >= 0)) {
    size_t inputlen = (size_t)length;
    size_t outputlen;
    CURLcode res = Curl_urldecode(string, inputlen, &str, &outputlen,
                                  REJECT_NADA);
    if(res)
      return NULL;

    if(olen) {
      if(outputlen <= (size_t) INT_MAX)
        *olen = curlx_uztosi(outputlen);
      else
        /* too large to return in an int, fail! */
        Curl_safefree(str);
    }
  }
  return str;
}

/* For operating systems/environments that use different malloc/free
   systems for the app and for this library, we provide a free that uses
   the library's memory system */
void curl_free(void *p)
{
  free(p);
}

/*
 * Curl_hexencode()
 *
 * Converts binary input to lowercase hex-encoded ASCII output.
 * Null-terminated.
 */
void Curl_hexencode(const unsigned char *src, size_t len, /* input length */
                    unsigned char *out, size_t olen) /* output buffer size */
{
  const char *hex = "0123456789abcdef";
  DEBUGASSERT(src && len && (olen >= 3));
  if(src && len && (olen >= 3)) {
    while(len-- && (olen >= 3)) {
      /* clang-tidy warns on this line without this comment: */
      /* NOLINTNEXTLINE(clang-analyzer-core.UndefinedBinaryOperatorResult) */
      *out++ = (unsigned char)hex[(*src & 0xF0) >> 4];
      *out++ = (unsigned char)hex[*src & 0x0F];
      ++src;
      olen -= 2;
    }
    *out = 0;
  }
  else if(olen)
    *out = 0;
}
