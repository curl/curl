/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "timeval.h"

#if defined(WIN32) && !defined(MSDOS)

struct curltime curlx_tvnow(void)
{
  /*
  ** GetTickCount() is available on _all_ Windows versions from W95 up
  ** to nowadays. Returns milliseconds elapsed since last system boot,
  ** increases monotonically and wraps once 49.7 days have elapsed.
  */
  struct curltime now;
#if !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_VISTA) || \
    (_WIN32_WINNT < _WIN32_WINNT_VISTA)
  DWORD milliseconds = GetTickCount();
  now.tv_sec = milliseconds / 1000;
  now.tv_usec = (milliseconds % 1000) * 1000;
#else
  ULONGLONG milliseconds = GetTickCount64();
  now.tv_sec = (time_t) (milliseconds / 1000);
  now.tv_usec = (unsigned int) (milliseconds % 1000) * 1000;
#endif

  return now;
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC)

struct curltime curlx_tvnow(void)
{
  /*
  ** clock_gettime() is granted to be increased monotonically when the
  ** monotonic clock is queried. Time starting point is unspecified, it
  ** could be the system start-up time, the Epoch, or something else,
  ** in any case the time starting point does not change once that the
  ** system has started up.
  */
  struct timeval now;
  struct curltime cnow;
  struct timespec tsnow;
  if(0 == clock_gettime(CLOCK_MONOTONIC, &tsnow)) {
    cnow.tv_sec = tsnow.tv_sec;
    cnow.tv_usec = (unsigned int)(tsnow.tv_nsec / 1000);
  }
  /*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** run-time. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
  else {
    (void)gettimeofday(&now, NULL);
    cnow.tv_sec = now.tv_sec;
    cnow.tv_usec = (unsigned int)now.tv_usec;
  }
#else
  else {
    cnow.tv_sec = time(NULL);
    cnow.tv_usec = 0;
  }
#endif
  return cnow;
}

#elif defined(HAVE_GETTIMEOFDAY)

struct curltime curlx_tvnow(void)
{
  /*
  ** gettimeofday() is not granted to be increased monotonically, due to
  ** clock drifting and external source time synchronization it can jump
  ** forward or backward in time.
  */
  struct timeval now;
  struct curltime ret;
  (void)gettimeofday(&now, NULL);
  ret.tv_sec = now.tv_sec;
  ret.tv_usec = now.tv_usec;
  return ret;
}

#else

struct curltime curlx_tvnow(void)
{
  /*
  ** time() returns the value of time in seconds since the Epoch.
  */
  struct curltime now;
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
  return now;
}

#endif

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we'll get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds. For large diffs it
 * returns 0x7fffffff on 32bit time_t systems.
 *
 * @unittest: 1323
 */
time_t curlx_tvdiff(struct curltime newer, struct curltime older)
{
#if SIZEOF_TIME_T < 8
  /* for 32bit time_t systems, add a precaution to avoid overflow for really
     big time differences */
  time_t diff = newer.tv_sec-older.tv_sec;
  if(diff >= (0x7fffffff/1000))
    return 0x7fffffff;
#endif
  return (newer.tv_sec-older.tv_sec)*1000+
    (int)(newer.tv_usec-older.tv_usec)/1000;
}

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we'll get a weird negative time-diff back...
 *
 * Returns: the time difference in number of microseconds. For too large diffs
 * it returns max value.
 */
time_t Curl_tvdiff_us(struct curltime newer, struct curltime older)
{
  time_t diff = newer.tv_sec-older.tv_sec;
#if SIZEOF_TIME_T < 8
  /* for 32bit time_t systems */
  if(diff >= (0x7fffffff/1000000))
    return 0x7fffffff;
#else
  /* for 64bit time_t systems */
  if(diff >= (0x7fffffffffffffffLL/1000000))
    return 0x7fffffffffffffffLL;
#endif
  return (newer.tv_sec-older.tv_sec)*1000000+
    (int)(newer.tv_usec-older.tv_usec);
}
