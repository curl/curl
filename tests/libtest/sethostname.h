/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef CURL_STATICLIB
#  define LIBHOSTNAME_EXTERN
#elif defined(WIN32)
#  define LIBHOSTNAME_EXTERN  __declspec(dllexport)
#elif defined(CURL_HIDDEN_SYMBOLS)
#  define LIBHOSTNAME_EXTERN CURL_EXTERN_SYMBOL
#else
#  define LIBHOSTNAME_EXTERN
#endif

#ifdef USE_WINSOCK
#  define FUNCALLCONV __stdcall
#else
#  define FUNCALLCONV
#endif

LIBHOSTNAME_EXTERN int FUNCALLCONV
  gethostname(char *name, GETHOSTNAME_TYPE_ARG2 namelen);
