#ifndef __TIMEVAL_H
#define __TIMEVAL_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

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
