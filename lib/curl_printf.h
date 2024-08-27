#ifndef HEADER_CURL_PRINTF_H
#define HEADER_CURL_PRINTF_H
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
 * This header should be included by ALL code in libcurl that uses any
 * *rintf() functions.
 */

/* Skip format checks for older mingw-w64 versions. They do not grok
   the `%zd` `%zu` formats by default, and there is format check CI
   coverage with newer mingw-w64 versions without them. */
#ifndef __MINGW64_VERSION_MAJOR
#error "__MINGW64_VERSION_MAJOR NOT DEFINED"
#elif __MINGW64_VERSION_MAJOR <= 7
#error "__MINGW64_VERSION_MAJOR 7 OR LOWER"
#endif

#if defined(__MINGW32__) && !defined(__clang__) && __MINGW64_VERSION_MAJOR <= 7
#define CURL_NO_FMT_CHECK_PUB
#error "DISABLING CURL_NO_FMT_CHECK_PUB"
#endif

#include <curl/mprintf.h>

#define MERR_OK        0
#define MERR_MEM       1
#define MERR_TOO_LARGE 2

# undef printf
# undef fprintf
# undef msnprintf
# undef vprintf
# undef vfprintf
# undef mvsnprintf
# undef aprintf
# undef vaprintf
# define printf curl_mprintf
# define fprintf curl_mfprintf
# define msnprintf curl_msnprintf
# define vprintf curl_mvprintf
# define vfprintf curl_mvfprintf
# define mvsnprintf curl_mvsnprintf
# define aprintf curl_maprintf
# define vaprintf curl_mvaprintf
#endif /* HEADER_CURL_PRINTF_H */
