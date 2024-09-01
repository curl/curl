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

#include <stdarg.h>
#include <stdio.h> /* needed for FILE */
#include "curl.h"  /* for CURL_EXTERN */

#ifdef  __cplusplus
extern "C" {
#endif

/* based on logic in "curl/mprintf.h" */

#if (defined(__GNUC__) || defined(__clang__) ||                         \
  defined(__IAR_SYSTEMS_ICC__)) &&                                      \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) &&         \
  !defined(CURL_NO_FMT_CHECKS)
#if defined(__MINGW32__) && !defined(__clang__)
#define CURL_PRINTF(fmt, arg) \
  __attribute__((format(gnu_printf, fmt, arg)))
#else
#define CURL_PRINTF(fmt, arg) \
  __attribute__((format(__printf__, fmt, arg)))
#endif
#else
#define CURL_PRINTF(fmt, arg)
#endif

CURL_EXTERN int curl_mprintf(const char *format, ...)
  CURL_TEMP_PRINTF(1, 2);
CURL_EXTERN int curl_mfprintf(FILE *fd, const char *format, ...)
  CURL_TEMP_PRINTF(2, 3);
CURL_EXTERN int curl_msprintf(char *buffer, const char *format, ...)
  CURL_TEMP_PRINTF(2, 3);
CURL_EXTERN int curl_msnprintf(char *buffer, size_t maxlength,
                               const char *format, ...)
  CURL_TEMP_PRINTF(3, 4);
CURL_EXTERN int curl_mvprintf(const char *format, va_list args)
  CURL_TEMP_PRINTF(1, 0);
CURL_EXTERN int curl_mvfprintf(FILE *fd, const char *format, va_list args)
  CURL_TEMP_PRINTF(2, 0);
CURL_EXTERN int curl_mvsprintf(char *buffer, const char *format, va_list args)
  CURL_TEMP_PRINTF(2, 0);
CURL_EXTERN int curl_mvsnprintf(char *buffer, size_t maxlength,
                                const char *format, va_list args)
  CURL_TEMP_PRINTF(3, 0);
CURL_EXTERN char *curl_maprintf(const char *format, ...)
  CURL_TEMP_PRINTF(1, 2);
CURL_EXTERN char *curl_mvaprintf(const char *format, va_list args)
  CURL_TEMP_PRINTF(1, 0);

#undef CURL_TEMP_PRINTF

#ifdef  __cplusplus
} /* end of extern "C" */
#endif

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
