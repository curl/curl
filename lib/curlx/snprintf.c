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
#if defined(WITHOUT_LIBCURL) && defined(_WIN32) /* when built for the test servers */
#include "curlx/snprintf.h"

#include <stdarg.h>

/* Wrapper for the Windows platform which uses the correct symbol and ensures
   to add a null-terminator */
void curlx_snprintf(char *buf, size_t maxlen, const char *fmt, ...)
{
  if(maxlen) {
    va_list ap;
    va_start(ap, fmt);
#if defined(_MSC_VER) && (_MSC_VER < 1900)
    (void)_snprintf(buf, maxlen, fmt, ap);
#else
    (void)snprintf(buf, maxlen, fmt, ap);
#endif
    /* Old versions of the Windows CRT do not terminate the snprintf output
       buffer if it reaches the max size so we do that here. */
    buf[maxlen - 1] = 0;
    va_end(ap);
  }
}
#endif /* WITHOUT_LIBCURL && _WIN32 */
