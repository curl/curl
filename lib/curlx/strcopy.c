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

#include "curlx/strcopy.h"

/*
 * curlx_strcopy() is a replacement for strcpy.
 *
 * Provide the target buffer @dest and size of the target buffer @dsize, If
 * the source string @src with its *string length* @slen fits in the target
 * buffer it will be copied there - including storing a null terminator.
 *
 * If the target buffer is too small, the copy is not performed but if the
 * target buffer has a non-zero size it will get a null terminator stored.
 */
void curlx_strcopy(char *dest,      /* destination buffer */
                   size_t dsize,    /* size of target buffer */
                   const char *src, /* source string */
                   size_t slen)     /* length of source string to copy */
{
  DEBUGASSERT(slen < dsize);
  if(slen < dsize) {
    memcpy(dest, src, slen);
    dest[slen] = 0;
  }
  else if(dsize)
    dest[0] = 0;
}
