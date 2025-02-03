#ifndef FETCHINC_MPRINTF_H
#define FETCHINC_MPRINTF_H
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

#include <stdarg.h>
#include <stdio.h> /* needed for FILE */
#include "fetch.h"  /* for FETCH_EXTERN */

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef FETCH_TEMP_PRINTF
#if (defined(__GNUC__) || defined(__clang__) ||                         \
  defined(__IAR_SYSTEMS_ICC__)) &&                                      \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) &&         \
  !defined(FETCH_NO_FMT_CHECKS)
#if defined(__MINGW32__) && !defined(__clang__)
#if defined(__MINGW_PRINTF_FORMAT)  /* mingw-w64 3.0.0+. Needs stdio.h. */
#define FETCH_TEMP_PRINTF(fmt, arg) \
  __attribute__((format(__MINGW_PRINTF_FORMAT, fmt, arg)))
#else
#define FETCH_TEMP_PRINTF(fmt, arg)
#endif
#else
#define FETCH_TEMP_PRINTF(fmt, arg) \
  __attribute__((format(printf, fmt, arg)))
#endif
#else
#define FETCH_TEMP_PRINTF(fmt, arg)
#endif
#endif

FETCH_EXTERN int fetch_mprintf(const char *format, ...)
  FETCH_TEMP_PRINTF(1, 2);
FETCH_EXTERN int fetch_mfprintf(FILE *fd, const char *format, ...)
  FETCH_TEMP_PRINTF(2, 3);
FETCH_EXTERN int fetch_msprintf(char *buffer, const char *format, ...)
  FETCH_TEMP_PRINTF(2, 3);
FETCH_EXTERN int fetch_msnprintf(char *buffer, size_t maxlength,
                               const char *format, ...)
  FETCH_TEMP_PRINTF(3, 4);
FETCH_EXTERN int fetch_mvprintf(const char *format, va_list args)
  FETCH_TEMP_PRINTF(1, 0);
FETCH_EXTERN int fetch_mvfprintf(FILE *fd, const char *format, va_list args)
  FETCH_TEMP_PRINTF(2, 0);
FETCH_EXTERN int fetch_mvsprintf(char *buffer, const char *format, va_list args)
  FETCH_TEMP_PRINTF(2, 0);
FETCH_EXTERN int fetch_mvsnprintf(char *buffer, size_t maxlength,
                                const char *format, va_list args)
  FETCH_TEMP_PRINTF(3, 0);
FETCH_EXTERN char *fetch_maprintf(const char *format, ...)
  FETCH_TEMP_PRINTF(1, 2);
FETCH_EXTERN char *fetch_mvaprintf(const char *format, va_list args)
  FETCH_TEMP_PRINTF(1, 0);

#undef FETCH_TEMP_PRINTF

#ifdef  __cplusplus
} /* end of extern "C" */
#endif

#endif /* FETCHINC_MPRINTF_H */
