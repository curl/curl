/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* The last #include file should be: */
#include "memdebug.h"

char *curl_escape(const char *string, int length)
{
  size_t alloc = (length?(size_t)length:strlen(string))+1;  
  char *ns;
  char *testing_ptr = NULL;
  unsigned char in;
  size_t newlen = alloc;
  int strindex=0;

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
      sprintf(&ns[strindex], "%%%02X", in);

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

#define ishex(in) ((in >= 'a' && in <= 'f') || \
                   (in >= 'A' && in <= 'F') || \
                   (in >= '0' && in <= '9'))

char *curl_unescape(const char *string, int length)
{
  int alloc = (length?length:(int)strlen(string))+1;
  char *ns = malloc(alloc);
  unsigned char in;
  int strindex=0;
  long hex;
 
  if( !ns )
    return NULL;
  
  while(--alloc > 0) {
    in = *string;
    if(('%' == in) && ishex(string[1]) && ishex(string[2])) {
      /* this is two hexadecimal digits following a '%' */
      char hexstr[3];
      char *ptr;
      hexstr[0] = string[1];
      hexstr[1] = string[2];
      hexstr[2] = 0;

      hex = strtol(hexstr, &ptr, 16);

      in = (unsigned char)hex; /* this long is never bigger than 255 anyway */
      string+=2;
      alloc-=2;
    }
    
    ns[strindex++] = in;
    string++;
  }
  ns[strindex]=0; /* terminate it */
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
