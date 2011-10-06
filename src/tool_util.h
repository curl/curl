#ifndef HEADER_CURL_TOOL_UTIL_H
#define HEADER_CURL_TOOL_UTIL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "setup.h"

struct timeval tool_tvnow(void);

/*
 * Make sure that the first argument (t1) is the more recent time and t2 is
 * the older time, as otherwise you get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
long tool_tvdiff(struct timeval t1, struct timeval t2);

/*
 * Same as tool_tvdiff but with full usec resolution.
 *
 * Returns: the time difference in seconds with subsecond resolution.
 */
double tool_tvdiff_secs(struct timeval t1, struct timeval t2);

long tool_tvlong(struct timeval t1);

#undef tvnow
#undef tvdiff
#undef tvdiff_secs
#undef tvlong

#define tvnow()           tool_tvnow()
#define tvdiff(a,b)       tool_tvdiff((a), (b))
#define tvdiff_secs(a,b)  tool_tvdiff_secs((a), (b))
#define tvlong(a)         tool_tvlong((a))

#endif /* HEADER_CURL_TOOL_UTIL_H */

