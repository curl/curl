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
#include "first.h"

#include "curl_memory.h"

#ifdef UNDER_CE
#define system_strdup _strdup
#else
#define system_strdup strdup
#endif

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(push)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(pop)
#endif
