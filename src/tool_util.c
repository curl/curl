/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#include "tool_util.h"

#include "memdebug.h" /* keep this as LAST include */

#if defined(WIN32) && !defined(MSDOS)

struct timeval tool_tvnow(void)
{
  /*
  ** GetTickCount() is available on _all_ Windows versions from W95 up
  ** to nowadays. Returns milliseconds elapsed since last system boot,
  ** increases monotonically and wraps once 49.7 days have elapsed.
  **
  ** GetTickCount64() is available on Windows version from Windows Vista
  ** and Windows Server 2008 up to nowadays. The resolution of the
  ** function is limited to the resolution of the system timer, which
  ** is typically in the range of 10 milliseconds to 16 milliseconds.
  */
  struct timeval now;
#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
  ULONGLONG milliseconds = GetTickCount64();
#else
  DWORD milliseconds = GetTickCount();
#endif
  now.tv_sec = (long)(milliseconds / 1000);
  now.tv_usec = (milliseconds % 1000) * 1000;
  return now;
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC)

struct timeval tool_tvnow(void)
{
  /*
  ** clock_gettime() is granted to be increased monotonically when the
  ** monotonic clock is queried. Time starting point is unspecified, it
  ** could be the system start-up time, the Epoch, or something else,
  ** in any case the time starting point does not change once that the
  ** system has started up.
  */
  struct timeval now;
  struct timespec tsnow;
  if(0 == clock_gettime(CLOCK_MONOTONIC, &tsnow)) {
    now.tv_sec = tsnow.tv_sec;
    now.tv_usec = tsnow.tv_nsec / 1000;
  }
  /*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** run-time. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
  else
    (void)gettimeofday(&now, NULL);
#else
  else {
    now.tv_sec = (long)time(NULL);
    now.tv_usec = 0;
  }
#endif
  return now;
}

#elif defined(HAVE_GETTIMEOFDAY)

struct timeval tool_tvnow(void)
{
  /*
  ** gettimeofday() is not granted to be increased monotonically, due to
  ** clock drifting and external source time synchronization it can jump
  ** forward or backward in time.
  */
  struct timeval now;
  (void)gettimeofday(&now, NULL);
  return now;
}

#else

struct timeval tool_tvnow(void)
{
  /*
  ** time() returns the value of time in seconds since the Epoch.
  */
  struct timeval now;
  now.tv_sec = (long)time(NULL);
  now.tv_usec = 0;
  return now;
}

#endif

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we'll get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
long tool_tvdiff(struct timeval newer, struct timeval older)
{
  return (newer.tv_sec-older.tv_sec)*1000+
    (newer.tv_usec-older.tv_usec)/1000;
}

/*
 * Same as tool_tvdiff but with full usec resolution.
 *
 * Returns: the time difference in seconds with subsecond resolution.
 */
double tool_tvdiff_secs(struct timeval newer, struct timeval older)
{
  if(newer.tv_sec != older.tv_sec)
    return (double)(newer.tv_sec-older.tv_sec)+
      (double)(newer.tv_usec-older.tv_usec)/1000000.0;
  else
    return (double)(newer.tv_usec-older.tv_usec)/1000000.0;
}

/* return the number of seconds in the given input timeval struct */
long tool_tvlong(struct timeval t1)
{
  return t1.tv_sec;
}

