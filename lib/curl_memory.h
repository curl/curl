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

#undef curlx_strdup
#undef curlx_malloc
#undef curlx_calloc
#undef curlx_realloc
#undef curlx_free
#undef curlx_tcsdup

#ifdef CURLDEBUG

#define curlx_strdup(ptr)         curl_dbg_strdup(ptr, __LINE__, __FILE__)
#define curlx_malloc(size)        curl_dbg_malloc(size, __LINE__, __FILE__)
#define curlx_calloc(nbelem,size) \
                              curl_dbg_calloc(nbelem, size, __LINE__, __FILE__)
#define curlx_realloc(ptr,size)   \
                              curl_dbg_realloc(ptr, size, __LINE__, __FILE__)
#define curlx_free(ptr)           curl_dbg_free(ptr, __LINE__, __FILE__)

#ifdef _WIN32
#ifdef UNICODE
#define curlx_tcsdup(ptr)         curl_dbg_wcsdup(ptr, __LINE__, __FILE__)
#else
#define curlx_tcsdup(ptr)         curlx_strdup(ptr)
#endif
#endif /* _WIN32 */

#else /* !CURLDEBUG */

#if !defined(CURL_STANDARD_ALLOC) || defined(CURL_STANDARD_LOCAL_OVERRIDE)
#undef curlx_strdup
#define curlx_strdup(ptr)         Curl_cstrdup(ptr)
#define curlx_malloc(size)        Curl_cmalloc(size)
#define curlx_calloc(nbelem,size) Curl_ccalloc(nbelem, size)
#define curlx_realloc(ptr,size)   Curl_crealloc(ptr, size)
#define curlx_free(ptr)           Curl_cfree(ptr)
#else /* CURL_STANDARD_ALLOC */
#ifdef _WIN32
#define curlx_strdup(ptr)         _strdup(ptr)
#else
#define curlx_strdup(ptr)         strdup(ptr)
#endif
#define curlx_malloc(size)        malloc(size)
#define curlx_calloc(nbelem,size) calloc(nbelem, size)
#define curlx_realloc(ptr,size)   realloc(ptr, size)
#define curlx_free(ptr)           free(ptr)
#endif /* !CURL_STANDARD_ALLOC */

#ifdef _WIN32
#ifdef UNICODE
#define curlx_tcsdup(ptr)         Curl_wcsdup(ptr)
#else
#define curlx_tcsdup(ptr)         curlx_strdup(ptr)
#endif
#endif /* _WIN32 */

#endif /* CURLDEBUG */
