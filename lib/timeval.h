#ifndef __TIMEVAL_H
#define __TIMEVAL_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <time.h>
#include <winsock.h>
#else
#include <sys/time.h>
#endif


#ifndef HAVE_GETTIMEOFDAY
#if !defined(_WINSOCKAPI_) && !defined(__MINGW32__)
struct timeval {
 long tv_sec;
 long tv_usec;
};
#endif
#endif

struct timeval Curl_tvnow (void);

/* the diff is from now on returned in number of milliseconds! */
long Curl_tvdiff (struct timeval t1, struct timeval t2);

long Curl_tvlong (struct timeval t1);

#endif
