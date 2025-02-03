#ifndef HEADER_FETCH_PRINTF_H
#define HEADER_FETCH_PRINTF_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * This header should be included by ALL code in libfetch that uses any
 * *rintf() functions.
 */

#ifndef FETCH_TEMP_PRINTF
#error "FETCH_TEMP_PRINTF must be set before including fetch/mprintf.h"
#endif

#include <fetch/mprintf.h>

#define MERR_OK 0
#define MERR_MEM 1
#define MERR_TOO_LARGE 2

#undef printf
#undef fprintf
#undef msnprintf
#undef vprintf
#undef vfprintf
#undef mvsnprintf
#undef aprintf
#undef vaprintf
#define printf fetch_mprintf
#define fprintf fetch_mfprintf
#define msnprintf fetch_msnprintf
#define vprintf fetch_mvprintf
#define vfprintf fetch_mvfprintf
#define mvsnprintf fetch_mvsnprintf
#define aprintf fetch_maprintf
#define vaprintf fetch_mvaprintf
#endif /* HEADER_FETCH_PRINTF_H */
