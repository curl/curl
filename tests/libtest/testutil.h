#ifndef HEADER_CURL_LIBTEST_TESTUTIL_H
#define HEADER_CURL_LIBTEST_TESTUTIL_H
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
#include "first.h"

/* build request url */
char *tutil_suburl(const char *base, int i);

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>  /* for getrlimit() */
#endif

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)
void tutil_rlim2str(char *buf, size_t len, rlim_t val);
#endif

#endif  /* HEADER_CURL_LIBTEST_TESTUTIL_H */
