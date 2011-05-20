/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#if (defined(WIN32) || defined(__SYMBIAN32__)) && !defined(CURL_STATICLIB)
#  if defined(BUILDING_LIBCURL)
#    define LIBHOSTNAME_EXTERN  __declspec(dllexport)
#  else
#    define LIBHOSTNAME_EXTERN  __declspec(dllimport)
#  endif
#else
#  ifdef CURL_HIDDEN_SYMBOLS
#    define LIBHOSTNAME_EXTERN CURL_EXTERN_SYMBOL
#  else
#    define LIBHOSTNAME_EXTERN
#  endif
#endif

#ifdef USE_WINSOCK
#  define FUNCALLCONV __stdcall
#else
#  define FUNCALLCONV
#endif

LIBHOSTNAME_EXTERN int FUNCALLCONV
  gethostname(char *name, GETHOSTNAME_TYPE_ARG2 namelen);

