/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

/* Escape and unescape URL encoding in strings. The functions return a new
 * allocated string or NULL if an error occurred.  */

#include "setup.h"
#include <ctype.h>
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "memory.h"
/* urldata.h and easyif.h are included for Curl_convert_... prototypes */
#include "urldata.h"
#include "easyif.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
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

char *curl_easy_escape(CURL *handle, const char *string, int inlength)
{
  size_t alloc = (inlength?(size_t)inlength:strlen(string))+1;
  char *ns;
  char *testing_ptr = NULL;
  unsigned char in;
  size_t newlen = alloc;
  int strindex=0;
  size_t length;

#ifndef CURL_DOES_CONVERSIONS
  /* avoid compiler warnings */
  (void)handle;
#endif
  ns = malloc(alloc);
  if(!ns)
    return NULL;

  length = alloc-1;
  while(length--) {
    in = *string;
    if(!(in >= 'a' && in <= 'z') &&
       !(in >= 'A' && in <= 'Z') &&
       !(in >= '0' && in <= '9')) {
      /* encode it */
      newlen += 2; /* the size grows with two, since this'll become a %XX */
      if(newlen > alloc) {
        alloc *= 2;
        testing_ptr = realloc(ns, alloc);
        if(!testing_ptr) {
          free( ns );
          return NULL;
        }
        else {
          ns = testing_ptr;
        }
      }

#ifdef CURL_DOES_CONVERSIONS
/* escape sequences are always in ASCII so convert them on non-ASCII hosts */
      if (!handle ||
          (Curl_convert_to_network(handle, &in, 1) != CURLE_OK)) {
        /* Curl_convert_to_network calls failf if unsuccessful */
        free(ns);
        return NULL;
      }
#endif /* CURL_DOES_CONVERSIONS */

      snprintf(&ns[strindex], 4, "%%%02X", in);

      strindex+=3;
    }
    else {
      /* just copy this */
      ns[strindex++]=in;
    }
    string++;
  }
  ns[strindex]=0; /* terminate it */
  return ns;
}

char *curl_easy_unescape(CURL *handle, const char *string, int length,
                         int *olen)
{
  int alloc = (length?length:(int)strlen(string))+1;
  char *ns = malloc(alloc);
  unsigned char in;
  int strindex=0;
  long hex;

#ifndef CURL_DOES_CONVERSIONS
  /* avoid compiler warnings */
  (void)handle;
#endif
  if( !ns )
    return NULL;

  while(--alloc > 0) {
    in = *string;
    if(('%' == in) && ISXDIGIT(string[1]) && ISXDIGIT(string[2])) {
      /* this is two hexadecimal digits following a '%' */
      char hexstr[3];
      char *ptr;
      hexstr[0] = string[1];
      hexstr[1] = string[2];
      hexstr[2] = 0;

      hex = strtol(hexstr, &ptr, 16);

      in = (unsigned char)hex; /* this long is never bigger than 255 anyway */

#ifdef CURL_DOES_CONVERSIONS
/* escape sequences are always in ASCII so convert them on non-ASCII hosts */
      if (!handle ||
          (Curl_convert_from_network(handle, &in, 1) != CURLE_OK)) {
        /* Curl_convert_from_network calls failf if unsuccessful */
        free(ns);
        return NULL;
      }
#endif /* CURL_DOES_CONVERSIONS */

      string+=2;
      alloc-=2;
    }

    ns[strindex++] = in;
    string++;
  }
  ns[strindex]=0; /* terminate it */

  if(olen)
    /* store output size */
    *olen = strindex;
  return ns;
}

/* For operating systems/environments that use different malloc/free
   ssystems for the app and for this library, we provide a free that uses
   the library's memory system */
void curl_free(void *p)
{
  if(p)
    free(p);
}
