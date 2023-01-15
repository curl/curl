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

/* Base64 encoding/decoding */

#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP_AUTH) || defined(USE_SSH) || \
  !defined(CURL_DISABLE_LDAP) || \
  !defined(CURL_DISABLE_SMTP) || \
  !defined(CURL_DISABLE_POP3) || \
  !defined(CURL_DISABLE_IMAP) || \
  !defined(CURL_DISABLE_DOH) || defined(USE_SSL)

#include "urldata.h" /* for the Curl_easy definition */
#include "warnless.h"
#include "curl_base64.h"

/* The last 2 #include files should be in this order */
#include "curl_memory.h"
#include "memdebug.h"

/* ---- Base64 Encoding/Decoding Table --- */
/* Padding character string starts at offset 64. */
static const char base64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/* The Base 64 encoding with a URL and filename safe alphabet, RFC 4648
   section 5 */
static const char base64url[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const unsigned char decodetable[] =
{ 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255,
  255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 26, 27, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
  48, 49, 50, 51 };
/*
 * Curl_base64_decode()
 *
 * Given a base64 NUL-terminated string at src, decode it and return a
 * pointer in *outptr to a newly allocated memory area holding decoded
 * data. Size of decoded data is returned in variable pointed by outlen.
 *
 * Returns CURLE_OK on success, otherwise specific error code. Function
 * output shall not be considered valid unless CURLE_OK is returned.
 *
 * When decoded data length is 0, returns NULL in *outptr.
 *
 * @unittest: 1302
 */
CURLcode Curl_base64_decode(const char *src,
                            unsigned char **outptr, size_t *outlen)
{
  size_t srclen = 0;
  size_t padding = 0;
  size_t i;
  size_t numQuantums;
  size_t fullQuantums;
  size_t rawlen = 0;
  unsigned char *pos;
  unsigned char *newstr;
  unsigned char lookup[256];

  *outptr = NULL;
  *outlen = 0;
  srclen = strlen(src);

  /* Check the length of the input string is valid */
  if(!srclen || srclen % 4)
    return CURLE_BAD_CONTENT_ENCODING;

  /* srclen is at least 4 here */
  while(src[srclen - 1 - padding] == '=') {
    /* count padding characters */
    padding++;
    /* A maximum of two = padding characters is allowed */
    if(padding > 2)
      return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Calculate the number of quantums */
  numQuantums = srclen / 4;
  fullQuantums = numQuantums - (padding ? 1 : 0);

  /* Calculate the size of the decoded string */
  rawlen = (numQuantums * 3) - padding;

  /* Allocate our buffer including room for a null-terminator */
  newstr = malloc(rawlen + 1);
  if(!newstr)
    return CURLE_OUT_OF_MEMORY;

  pos = newstr;

  memset(lookup, 0xff, sizeof(lookup));
  memcpy(&lookup['+'], decodetable, sizeof(decodetable));
  /* replaces
  {
    unsigned char c;
    const unsigned char *p = (const unsigned char *)base64;
    for(c = 0; *p; c++, p++)
      lookup[*p] = c;
  }
  */

  /* Decode the complete quantums first */
  for(i = 0; i < fullQuantums; i++) {
    unsigned char val;
    unsigned int x = 0;
    int j;

    for(j = 0; j < 4; j++) {
      val = lookup[(unsigned char)*src++];
      if(val == 0xff) /* bad symbol */
        goto bad;
      x = (x << 6) | val;
    }
    pos[2] = x & 0xff;
    pos[1] = (x >> 8) & 0xff;
    pos[0] = (x >> 16) & 0xff;
    pos += 3;
  }
  if(padding) {
    /* this means either 8 or 16 bits output */
    unsigned char val;
    unsigned int x = 0;
    int j;
    size_t padc = 0;
    for(j = 0; j < 4; j++) {
      if(*src == '=') {
        x <<= 6;
        src++;
        if(++padc > padding)
          /* this is a badly placed '=' symbol! */
          goto bad;
      }
      else {
        val = lookup[(unsigned char)*src++];
        if(val == 0xff) /* bad symbol */
          goto bad;
        x = (x << 6) | val;
      }
    }
    if(padding == 1)
      pos[1] = (x >> 8) & 0xff;
    pos[0] = (x >> 16) & 0xff;
    pos += 3 - padding;
  }

  /* Zero terminate */
  *pos = '\0';

  /* Return the decoded data */
  *outptr = newstr;
  *outlen = rawlen;

  return CURLE_OK;
  bad:
  free(newstr);
  return CURLE_BAD_CONTENT_ENCODING;
}

static CURLcode base64_encode(const char *table64,
                              const char *inputbuff, size_t insize,
                              char **outptr, size_t *outlen)
{
  char *output;
  char *base64data;
  const unsigned char *in = (unsigned char *)inputbuff;
  const char *padstr = &table64[64];    /* Point to padding string. */

  *outptr = NULL;
  *outlen = 0;

  if(!insize)
    insize = strlen(inputbuff);

#if SIZEOF_SIZE_T == 4
  if(insize > UINT_MAX/4)
    return CURLE_OUT_OF_MEMORY;
#endif

  base64data = output = malloc((insize + 2) / 3 * 4 + 1);
  if(!output)
    return CURLE_OUT_OF_MEMORY;

  while(insize >= 3) {
    *output++ = table64[ in[0] >> 2 ];
    *output++ = table64[ ((in[0] & 0x03) << 4) | (in[1] >> 4) ];
    *output++ = table64[ ((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6) ];
    *output++ = table64[ in[2] & 0x3F ];
    insize -= 3;
    in += 3;
  }
  if(insize) {
    /* this is only one or two bytes now */
    *output++ = table64[ in[0] >> 2 ];
    if(insize == 1) {
      *output++ = table64[ ((in[0] & 0x03) << 4) ];
      if(*padstr) {
        *output++ = *padstr;
        *output++ = *padstr;
      }
    }
    else {
      /* insize == 2 */
      *output++ = table64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4) ];
      *output++ = table64[ ((in[1] & 0x0F) << 2) ];
      if(*padstr)
        *output++ = *padstr;
    }
  }

  /* Zero terminate */
  *output = '\0';

  /* Return the pointer to the new data (allocated memory) */
  *outptr = base64data;

  /* Return the length of the new data */
  *outlen = output - base64data;

  return CURLE_OK;
}

/*
 * Curl_base64_encode()
 *
 * Given a pointer to an input buffer and an input size, encode it and
 * return a pointer in *outptr to a newly allocated memory area holding
 * encoded data. Size of encoded data is returned in variable pointed by
 * outlen.
 *
 * Input length of 0 indicates input buffer holds a NUL-terminated string.
 *
 * Returns CURLE_OK on success, otherwise specific error code. Function
 * output shall not be considered valid unless CURLE_OK is returned.
 *
 * @unittest: 1302
 */
CURLcode Curl_base64_encode(const char *inputbuff, size_t insize,
                            char **outptr, size_t *outlen)
{
  return base64_encode(base64, inputbuff, insize, outptr, outlen);
}

/*
 * Curl_base64url_encode()
 *
 * Given a pointer to an input buffer and an input size, encode it and
 * return a pointer in *outptr to a newly allocated memory area holding
 * encoded data. Size of encoded data is returned in variable pointed by
 * outlen.
 *
 * Input length of 0 indicates input buffer holds a NUL-terminated string.
 *
 * Returns CURLE_OK on success, otherwise specific error code. Function
 * output shall not be considered valid unless CURLE_OK is returned.
 *
 * @unittest: 1302
 */
CURLcode Curl_base64url_encode(const char *inputbuff, size_t insize,
                               char **outptr, size_t *outlen)
{
  return base64_encode(base64url, inputbuff, insize, outptr, outlen);
}

#endif /* no users so disabled */
