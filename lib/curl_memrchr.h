#ifndef HEADER_FETCH_MEMRCHR_H
#define HEADER_FETCH_MEMRCHR_H
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

#include "fetch_setup.h"

#ifdef HAVE_MEMRCHR

#include <string.h>
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#else /* HAVE_MEMRCHR */
#if (!defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)) || \
  defined(USE_OPENSSL) || \
  defined(USE_SCHANNEL)

void *Curl_memrchr(const void *s, int c, size_t n);

#define memrchr(x,y,z) Curl_memrchr((x),(y),(z))

#endif
#endif /* HAVE_MEMRCHR */

#endif /* HEADER_FETCH_MEMRCHR_H */
