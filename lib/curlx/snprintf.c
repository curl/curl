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
#include "curlx/snprintf.h"

#ifdef _WIN32
#include <stdarg.h>

/* Simplified wrapper for the Windows platform to use the correct symbol and
   ensure to add a null-terminator. Omit the length to keep it simple. */
void curlx_win32_snprintf(char *buf, size_t maxlen, const char *fmt, ...)
{
  va_list ap;
  if(!maxlen)
    return;
  va_start(ap, fmt);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  /* !checksrc! disable BANNEDFUNC 1 */
  (void)vsnprintf(buf, maxlen, fmt, ap);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
  va_end(ap);
}
#endif /* _WIN32 */
