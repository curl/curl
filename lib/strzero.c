/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Gustafsson, <daniel@yesql.se>, et.al
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

#include "strzero.h"

/*
 * Curl_explicit_bzero zeroes out a memory buffer in such a way to ensure that
 * it won't be optimized away by the compiler due to being a dead-store. If no
 * API for this exists it will fall back to plain memset using a volatile ptr.
 */

#if defined(_WIN32)
#include <windows.h>
void
Curl_explicit_bzero(void *buffer, size_t length)
{
  if(!buffer)
    return;
  /*
   * Windows 11 ships a new function SecureZeroMemory2 which is a safer
   * method, but might not be as widely available as SecureZeroMemory is
   * which exist all the way back to Windows XP.
   */
#ifdef SecureZeroMemory2
  (void)SecureZeroMemory2(buffer, length);
#else
  (void)SecureZeroMemory(buffer, length);
#endif
}
#elif defined(HAVE_MEMSET_S)
void
Curl_explicit_bzero(void *buffer, size_t length)
{
  if(!buffer)
    return;
  (void)memset_s(buffer, length, 0, length);
}
#elif defined(HAVE_EXPLICIT_BZERO)
Curl_explicit_bzero(void *buffer, size_t length)
{
  if(!buffer)
    return;
  explicit_bzero(buffer, length);
}
#elif defined(HAVE_EXPLICIT_MEMSET)
Curl_explicit_bzero(void *buffer, size_t length)
{
  if(!buffer)
    return;
  (void)explicit_memset(buffer, 0, length);
}
#else

/*
 * If no other method is available, make an indirect call via a volatile
 * pointer to try and evade compiler optimizations. This trick was invented
 * by OpenSSH, later followed by PostgreSQL.
 */
static void
memset_vol(void *buffer, size_t length)
{
  memset(buffer, 0, length);
}

static void
(*volatile memset_vol_ptr) (void *buffer, size_t length) = memset_vol;

void
Curl_explicit_bzero(void *buffer, size_t length)
{
  if(!buffer)
    return;
  memset_vol_ptr(buffer, length);
}

#endif
