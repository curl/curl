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

#include "curl_setup.h"

#include <curl/curl.h>

#ifdef _WIN32
#include <wchar.h>
#endif

#include "strdup.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

#ifndef HAVE_STRDUP
char *Curl_strdup(const char *str)
{
  size_t len;
  char *newstr;

  if(!str)
    return (char *)NULL;

  len = strlen(str) + 1;

  newstr = MALLOC(len);
  if(!newstr)
    return (char *)NULL;

  memcpy(newstr, str, len);
  return newstr;
}
#endif

#ifdef _WIN32
/***************************************************************************
 *
 * Curl_wcsdup(source)
 *
 * Copies the 'source' wchar string to a newly allocated buffer (that is
 * returned).
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
wchar_t *Curl_wcsdup(const wchar_t *src)
{
  size_t length = wcslen(src);

  if(length > (SIZE_T_MAX / sizeof(wchar_t)) - 1)
    return (wchar_t *)NULL; /* integer overflow */

  return (wchar_t *)Curl_memdup(src, (length + 1) * sizeof(wchar_t));
}
#endif

/***************************************************************************
 *
 * Curl_memdup(source, length)
 *
 * Copies the 'source' data to a newly allocated buffer (that is
 * returned). Copies 'length' bytes.
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
void *Curl_memdup(const void *src, size_t length)
{
  void *buffer = MALLOC(length);
  if(!buffer)
    return NULL; /* fail */

  memcpy(buffer, src, length);

  return buffer;
}

/***************************************************************************
 *
 * Curl_memdup0(source, length)
 *
 * Copies the 'source' string to a newly allocated buffer (that is returned).
 * Copies 'length' bytes then adds a null terminator.
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
void *Curl_memdup0(const char *src, size_t length)
{
  char *buf = MALLOC(length + 1);
  if(!buf)
    return NULL;
  if(length) {
    DEBUGASSERT(src); /* must never be NULL */
    memcpy(buf, src, length);
  }
  buf[length] = 0;
  return buf;
}

/***************************************************************************
 *
 * Curl_saferealloc(ptr, size)
 *
 * Does a normal REALLOC(), but will free the data pointer if the realloc
 * fails. If 'size' is non-zero, it will free the data and return a failure.
 *
 * This convenience function is provided and used to help us avoid a common
 * mistake pattern when we could pass in a zero, catch the NULL return and end
 * up free'ing the memory twice.
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
void *Curl_saferealloc(void *ptr, size_t size)
{
  void *datap = REALLOC(ptr, size);
  if(size && !datap)
    /* only free 'ptr' if size was non-zero */
    FREE(ptr);
  return datap;
}
