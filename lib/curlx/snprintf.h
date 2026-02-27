#ifndef HEADER_CURLX_SNPRINTF_H
#define HEADER_CURLX_SNPRINTF_H
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

/* Raw snprintf() for curlx */

#ifdef _WIN32
int curlx_win32_snprintf(char *buf, size_t maxlen, const char *fmt, ...)
  CURL_PRINTF(3, 4);
#endif

#ifdef WITHOUT_LIBCURL /* when built for the test servers */
#ifdef _WIN32
#define SNPRINTF curlx_win32_snprintf
#else
#define SNPRINTF snprintf
#endif
#else /* !WITHOUT_LIBCURL */
#include <curl/mprintf.h>
#define SNPRINTF curl_msnprintf
#endif /* WITHOUT_LIBCURL */
#endif /* HEADER_CURLX_SNPRINTF_H */
