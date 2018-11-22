/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* Escape and unescape URL encoding in strings. The functions return a new
 * allocated string or NULL if an error occurred.  */

#include "curl_setup.h"

#include <curl/curl.h>

#include "urldata.h"
#include "warnless.h"
#include "non-ascii.h"
#include "escape.h"
#include "strdup.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* Portable character check (remember EBCDIC). Do not use isalnum() because
   its behavior is altered by the current locale.
   See https://tools.ietf.org/html/rfc3986#section-2.3
*/
bool Curl_isunreserved(unsigned char in)
{
  switch(in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f': case 'g': case 'h': case 'i': case 'j':
    case 'k': case 'l': case 'm': case 'n': case 'o':
    case 'p': case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F': case 'G': case 'H': case 'I': case 'J':
    case 'K': case 'L': case 'M': case 'N': case 'O':
    case 'P': case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case '-': case '.': case '_': case '~':
      return TRUE;
    default:
      break;
  }
  return FALSE;
}

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

char *curl_easy_escape(struct Curl_easy *data, const char *string,
                       int inlength)
{
  size_t alloc;
  char *ns;
  char *testing_ptr = NULL;
  size_t newlen;
  size_t strindex = 0;
  size_t length;
  CURLcode result;

  if(inlength < 0)
    return NULL;

  alloc = (inlength?(size_t)inlength:strlen(string)) + 1;
  newlen = alloc;

  ns = malloc(alloc);
  if(!ns)
    return NULL;

  length = alloc-1;
  while(length--) {
    unsigned char in = *string; /* we need to treat the characters unsigned */

    if(Curl_isunreserved(in))
      /* just copy this */
      ns[strindex++] = in;
    else {
      /* encode it */
      newlen += 2; /* the size grows with two, since this'll become a %XX */
      if(newlen > alloc) {
        alloc *= 2;
        testing_ptr = Curl_saferealloc(ns, alloc);
        if(!testing_ptr)
          return NULL;
        ns = testing_ptr;
      }

      result = Curl_convert_to_network(data, (char *)&in, 1);
      if(result) {
        /* Curl_convert_to_network calls failf if unsuccessful */
        free(ns);
        return NULL;
      }

      msnprintf(&ns[strindex], 4, "%%%02X", in);

      strindex += 3;
    }
    string++;
  }
  ns[strindex] = 0; /* terminate it */
  return ns;
}

/*
 * Curl_urldecode() URL decodes the given string.
 *
 * Optionally detects control characters (byte codes lower than 32) in the
 * data and rejects such data.
 *
 * Returns a pointer to a malloced string in *ostring with length given in
 * *olen. If length == 0, the length is assumed to be strlen(string).
 *
 * 'data' can be set to NULL but then this function can't convert network
 * data to host for non-ascii.
 */
CURLcode Curl_urldecode(struct Curl_easy *data,
                        const char *string, size_t length,
                        char **ostring, size_t *olen,
                        bool reject_ctrl)
{
  size_t alloc = (length?length:strlen(string)) + 1;
  char *ns = malloc(alloc);
  size_t strindex = 0;
  unsigned long hex;
  CURLcode result = CURLE_OK;

  if(!ns)
    return CURLE_OUT_OF_MEMORY;

  while(--alloc > 0) {
    unsigned char in = *string;
    if(('%' == in) && (alloc > 2) &&
       ISXDIGIT(string[1]) && ISXDIGIT(string[2])) {
      /* this is two hexadecimal digits following a '%' */
      char hexstr[3];
      char *ptr;
      hexstr[0] = string[1];
      hexstr[1] = string[2];
      hexstr[2] = 0;

      hex = strtoul(hexstr, &ptr, 16);

      in = curlx_ultouc(hex); /* this long is never bigger than 255 anyway */

      if(data) {
        result = Curl_convert_from_network(data, (char *)&in, 1);
        if(result) {
          /* Curl_convert_from_network calls failf if unsuccessful */
          free(ns);
          return result;
        }
      }

      string += 2;
      alloc -= 2;
    }

    if(reject_ctrl && (in < 0x20)) {
      free(ns);
      return CURLE_URL_MALFORMAT;
    }

    ns[strindex++] = in;
    string++;
  }
  ns[strindex] = 0; /* terminate it */

  if(olen)
    /* store output size */
    *olen = strindex;

  /* store output string */
  *ostring = ns;

  return CURLE_OK;
}

/*
 * Unescapes the given URL escaped string of given length. Returns a
 * pointer to a malloced string with length given in *olen.
 * If length == 0, the length is assumed to be strlen(string).
 * If olen == NULL, no output length is stored.
 */
char *curl_easy_unescape(struct Curl_easy *data, const char *string,
                         int length, int *olen)
{
  char *str = NULL;
  if(length >= 0) {
    size_t inputlen = length;
    size_t outputlen;
    CURLcode res = Curl_urldecode(data, string, inputlen, &str, &outputlen,
                                  FALSE);
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
