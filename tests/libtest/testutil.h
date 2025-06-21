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
#include "test.h"

struct timeval tutil_tvnow(void);

/*
 * Make sure that the first argument (t1) is the more recent time and t2 is
 * the older time, as otherwise you get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
long tutil_tvdiff(struct timeval t1, struct timeval t2);

/*
 * Same as tutil_tvdiff but with full usec resolution.
 *
 * Returns: the time difference in seconds with subsecond resolution.
 */
double tutil_tvdiff_secs(struct timeval t1, struct timeval t2);

/* build request url */
char *tutil_suburl(const char *base, int i);

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <limits.h>

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)
void tutil_rlim2str(char *buf, size_t len, rlim_t val);
#endif

#endif  /* HEADER_CURL_LIBTEST_TESTUTIL_H */
