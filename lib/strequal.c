/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <string.h>

int Curl_strequal(const char *first, const char *second)
{
#if defined(HAVE_STRCASECMP)
  return !strcasecmp(first, second);
#elif defined(HAVE_STRCMPI)
  return !strcmpi(first, second);
#elif defined(HAVE_STRICMP)
  return !stricmp(first, second);
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

int Curl_strnequal(const char *first, const char *second, size_t max)
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
  return toupper(*first) == toupper(*second);
#endif
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
 */
size_t strlcat(char *dst, const char *src, size_t size)
{
  size_t len = strlen(dst);
  size_t orglen = len;
  int index=0;
  
  while(src[index] && (len < (size-1)) ) {
    dst[len++] = src[index++];
  }
  dst[len]=0;

  return orglen + strlen(src);
}
#endif
