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

#include "setup.h"

#include <string.h>
#include <ctype.h>

#include "strequal.h"

#ifdef HAVE_STRCASECMP
/* this is for "-ansi -Wall -pedantic" to stop complaining! */
extern int (strcasecmp)(const char *s1, const char *s2);
extern int (strncasecmp)(const char *s1, const char *s2, size_t n);
#endif

int curl_strequal(const char *first, const char *second)
{
#if defined(HAVE_STRCASECMP)
  return !(strcasecmp)(first, second);
#elif defined(HAVE_STRCMPI)
  return !(strcmpi)(first, second);
#elif defined(HAVE_STRICMP)
  return !(stricmp)(first, second);
#else
  while (*first && *second) {
    if (toupper(*first) != toupper(*second)) {
      break;
    }
    first++;
    second++;
  }
  return toupper(*first) == toupper(*second);
#endif
}

int curl_strnequal(const char *first, const char *second, size_t max)
{
#if defined(HAVE_STRCASECMP)
  return !strncasecmp(first, second, max);
#elif defined(HAVE_STRCMPI)
  return !strncmpi(first, second, max);
#elif defined(HAVE_STRICMP)
  return !strnicmp(first, second, max);
#else
  while (*first && *second && max) {
    if (toupper(*first) != toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return toupper(*first) == toupper(*second);
#endif
}

/*
 * Curl_strcasestr() finds the first occurrence of the substring needle in the
 * string haystack.  The terminating `\0' characters are not compared. The
 * matching is done CASE INSENSITIVE, which thus is the difference between
 * this and strstr().
 */
char *Curl_strcasestr(const char *haystack, const char *needle)
{
  size_t nlen = strlen(needle);
  size_t hlen = strlen(haystack);

  while(hlen-- >= nlen) {
    if(curl_strnequal(haystack, needle, nlen))
      return (char *)haystack;
    haystack++;
  }
  return NULL;
}

#ifndef HAVE_STRLCAT
/*
 * The strlcat() function appends the NUL-terminated string src to the end
 * of dst. It will append at most size - strlen(dst) - 1 bytes, NUL-termi-
 * nating the result.
 *
 * The strlcpy() and strlcat() functions return the total length of the
 * string they tried to create.  For strlcpy() that means the length of src.
 * For strlcat() that means the initial length of dst plus the length of
 * src. While this may seem somewhat confusing it was done to make trunca-
 * tion detection simple.
 *
 *
 */
size_t Curl_strlcat(char *dst, const char *src, size_t siz)
{
  char *d = dst;
  const char *s = src;
  size_t n = siz;
  size_t dlen;

  /* Find the end of dst and adjust bytes left but don't go past end */
  while (n-- != 0 && *d != '\0')
    d++;
  dlen = d - dst;
  n = siz - dlen;

  if (n == 0)
    return(dlen + strlen(s));
  while (*s != '\0') {
    if (n != 1) {
      *d++ = *s;
      n--;
    }
    s++;
  }
  *d = '\0';

  return(dlen + (s - src));	/* count does not include NUL */
}
#endif
