#ifndef HEADER_LIBTEST_FIRST_H
#define HEADER_LIBTEST_FIRST_H
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
#define CURL_DISABLE_DEPRECATION 1
#include "curl_setup.h"
#include <curl/curl.h>

typedef CURLcode (*test_func_t)(char *);

#ifdef CURLTESTS_BUNDLED
struct onetest {
  const char *name;
  test_func_t ptr;
};
#endif

#endif /* HEADER_LIBTEST_FIRST_H */
