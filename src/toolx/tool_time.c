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
#include "toolx/tool_time.h"

#if defined(__MINGW32__) && (__MINGW64_VERSION_MAJOR <= 3)
#include <sec_api/time_s.h>  /* for _localtime32_s(), _localtime64_s() */
#ifdef _USE_32BIT_TIME_T
#define localtime_s _localtime32_s
#else
#define localtime_s _localtime64_s
#endif
#endif

/*
 * toolx_localtime() is a localtime() replacement for portability. Do not use
 * the localtime_s(), localtime_r() or localtime() functions anywhere else but
 * here.
 */
CURLcode toolx_localtime(time_t intime, struct tm *store)
{
#ifdef _WIN32
  if(localtime_s(store, &intime)) /* thread-safe */
    return CURLE_BAD_FUNCTION_ARGUMENT;
#elif defined(HAVE_LOCALTIME_R)
  const struct tm *tm;
  tm = localtime_r(&intime, store); /* thread-safe */
  if(!tm)
    return CURLE_BAD_FUNCTION_ARGUMENT;
#else
  const struct tm *tm;
  /* !checksrc! disable BANNEDFUNC 1 */
  tm = localtime(&intime); /* not thread-safe */
  if(tm)
    *store = *tm; /* copy the pointed struct to the local copy */
  else
    return CURLE_BAD_FUNCTION_ARGUMENT;
#endif

  return CURLE_OK;
}
