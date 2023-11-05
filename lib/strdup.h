#ifndef HEADER_CURL_STRDUP_H
#define HEADER_CURL_STRDUP_H
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

#ifndef BUILDING_LIBCURL
/* this renames functions so that the tool code can use the same code
   without getting symbol collisions */
#define Curl_strdup(ptr) curlx_strdup(ptr)
#define Curl_strndup(ptr,size) curlx_strndup(ptr,size)
#define Curl_wcsdup(ptr) curlx_wcsdup(ptr)
#define Curl_memdup(ptr,size) curlx_memdup(ptr,size)
#define Curl_saferealloc(ptr,size) curlx_saferealloc(ptr,size)
#endif

#ifndef HAVE_STRDUP
char *Curl_strdup(const char *str);
#define strdup Curl_strdup
#else
#include <string.h>
#endif

#ifndef HAVE_STRNDUP
void *Curl_strndup(const char *src, size_t length);
#define strndup Curl_strndup
#else
#include <string.h>
#endif

#ifdef WIN32
wchar_t* Curl_wcsdup(const wchar_t* src);
#endif
void *Curl_memdup(const void *src, size_t buffer_length);
void *Curl_saferealloc(void *ptr, size_t size);

#endif /* HEADER_CURL_STRDUP_H */
