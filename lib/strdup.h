#ifndef HEADER_FETCH_STRDUP_H
#define HEADER_FETCH_STRDUP_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetch_setup.h"

#ifndef HAVE_STRDUP
char *Fetch_strdup(const char *str);
#endif
#ifdef _WIN32
wchar_t *Fetch_wcsdup(const wchar_t *src);
#endif
void *Fetch_memdup(const void *src, size_t buffer_length);
void *Fetch_saferealloc(void *ptr, size_t size);
void *Fetch_memdup0(const char *src, size_t length);

#endif /* HEADER_FETCH_STRDUP_H */
