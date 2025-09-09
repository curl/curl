#ifndef HEADER_CURL_MEMDEBUG_H
#define HEADER_CURL_MEMDEBUG_H
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

/*
 * CAUTION: this header is designed to work when included by the app-side
 * as well as the library. Do not mix with library internals!
 */

#ifdef CURLDEBUG

/* Set this symbol on the command-line, recompile all lib-sources */
#undef strdup
#define strdup(ptr) curl_dbg_strdup(ptr, __LINE__, __FILE__)
#undef malloc
#define malloc(size) curl_dbg_malloc(size, __LINE__, __FILE__)
#undef calloc
#define calloc(nbelem,size) curl_dbg_calloc(nbelem, size, __LINE__, __FILE__)
#undef realloc
#define realloc(ptr,size) curl_dbg_realloc(ptr, size, __LINE__, __FILE__)
#undef free
#define free(ptr) curl_dbg_free(ptr, __LINE__, __FILE__)

#ifdef _WIN32
#undef Curl_tcsdup
#ifdef UNICODE
#define Curl_tcsdup(ptr) curl_dbg_wcsdup(ptr, __LINE__, __FILE__)
#else
#define Curl_tcsdup(ptr) curl_dbg_strdup(ptr, __LINE__, __FILE__)
#endif
#endif /* _WIN32 */

#undef fopen
#define fopen(file,mode) curl_dbg_fopen(file,mode,__LINE__,__FILE__)
#undef fdopen
#define fdopen(file,mode) curl_dbg_fdopen(file,mode,__LINE__,__FILE__)
#undef fclose
#define fclose(file) curl_dbg_fclose(file,__LINE__,__FILE__)

#endif /* CURLDEBUG */
#endif /* HEADER_CURL_MEMDEBUG_H */
