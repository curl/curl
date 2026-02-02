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
#include "../curl_setup.h"

#ifdef _WIN32
#include <wchar.h>
#endif

#include "strdup.h"

#ifdef _WIN32
/***************************************************************************
 *
 * curlx_wcsdup(source)
 *
 * Copies the 'source' wchar string to a newly allocated buffer (that is
 * returned). Used by macro curlx_tcsdup().
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
wchar_t *curlx_wcsdup(const wchar_t *src)
{
  size_t length = wcslen(src);

  if(length > (SIZE_MAX / sizeof(wchar_t)) - 1)
    return (wchar_t *)NULL; /* integer overflow */

  return (wchar_t *)curlx_memdup(src, (length + 1) * sizeof(wchar_t));
}
#endif

/***************************************************************************
 *
 * curlx_memdup(source, length)
 *
 * Copies the 'source' data to a newly allocated buffer (that is
 * returned). Copies 'length' bytes.
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
void *curlx_memdup(const void *src, size_t length)
{
  void *buffer = curlx_malloc(length);
  if(!buffer)
    return NULL; /* fail */

  memcpy(buffer, src, length);

  return buffer;
}

/***************************************************************************
 *
 * curlx_memdup0(source, length)
 *
 * Copies the 'source' string to a newly allocated buffer (that is returned).
 * Copies 'length' bytes then adds a null-terminator.
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
void *curlx_memdup0(const char *src, size_t length)
{
  char *buf = (length < SIZE_MAX) ? curlx_malloc(length + 1) : NULL;
  if(!buf)
    return NULL;
  if(length) {
    DEBUGASSERT(src); /* must never be NULL */
    memcpy(buf, src, length);
  }
  buf[length] = 0;
  return buf;
}
