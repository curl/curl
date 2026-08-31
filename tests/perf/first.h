#ifndef HEADER_PERF_FIRST_H
#define HEADER_PERF_FIRST_H
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
#define CURL_NO_OLDIES
#define CURL_DISABLE_DEPRECATION

/* Now include the curl_setup.h file from libcurl's private libdir (the source
   version, but that might include "curl_config.h" from the build directory so
   we need both of them in the include path), so that we get good in-depth
   knowledge about the system we are building this on */
#include "curl_setup.h"

#include "curlx/base64.h" /* for curlx_base64* */
#include "curlx/fopen.h" /* for curlx_f*() */
#include "curlx/strparse.h" /* for curlx_str_* parsing functions */
#include "curlx/timeval.h" /* for curlx_now type and related functions */

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

typedef int (*entry_func_t)(int, const char **);

struct entry_s {
  const char *name;
  entry_func_t ptr;
};

extern const struct entry_s s_entries[];

#endif /* HEADER_PERF_FIRST_H */
