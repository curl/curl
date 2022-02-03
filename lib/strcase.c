/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "strcase.h"

static char raw_tolower(char in);

/* Portable, consistent toupper. Do not use toupper() because its behavior is
   altered by the current locale. */
char Curl_raw_toupper(char in)
{
  if(in >= 'a' && in <= 'z')
    return (char)('A' + in - 'a');
  return in;
}


/* Portable, consistent tolower. Do not use tolower() because its behavior is
   altered by the current locale. */
static char raw_tolower(char in)
{
  if(in >= 'A' && in <= 'Z')
    return (char)('a' + in - 'A');
  return in;
}

/*
 * Curl_strcasecompare() is for doing "raw" case insensitive strings. This is
 * meant to be locale independent and only compare strings we know are safe
 * for this.  See
 * https://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for some
 * further explanation to why this function is necessary.
 *
 * @unittest: 1301
 */

int Curl_strcasecompare(const char *first, const char *second)
{
  while(*first && *second) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second))
      /* get out of the loop as soon as they don't match */
      break;
    first++;
    second++;
  }
  /* we do the comparison here (possibly again), just to make sure that if the
     loop above is skipped because one of the strings reached zero, we must not
     return this as a successful match */
  return (Curl_raw_toupper(*first) == Curl_raw_toupper(*second));
}

int Curl_safe_strcasecompare(const char *first, const char *second)
{
  if(first && second)
    /* both pointers point to something then compare them */
    return Curl_strcasecompare(first, second);

  /* if both pointers are NULL then treat them as equal */
  return (NULL == first && NULL == second);
}

/*
 * @unittest: 1301
 */
int Curl_strncasecompare(const char *first, const char *second, size_t max)
{
  while(*first && *second && max) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return Curl_raw_toupper(*first) == Curl_raw_toupper(*second);
}

/* Copy an upper case version of the string from src to dest.  The
 * strings may overlap.  No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void Curl_strntoupper(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = Curl_raw_toupper(*src);
  } while(*src++ && --n);
}

/* Copy a lower case version of the string from src to dest.  The
 * strings may overlap.  No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void Curl_strntolower(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = raw_tolower(*src);
  } while(*src++ && --n);
}

/* --- public functions --- */

int curl_strequal(const char *first, const char *second)
{
  return Curl_strcasecompare(first, second);
}
int curl_strnequal(const char *first, const char *second, size_t max)
{
  return Curl_strncasecompare(first, second, max);
}
