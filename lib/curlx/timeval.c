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

#include "timeval.h"

#ifdef _WIN32

#include <curl/curl.h>
#include "version_win32.h"
#include "../system_win32.h"

LARGE_INTEGER Curl_freq;
bool Curl_isVistaOrGreater;

/* For tool or tests, we must initialize before calling curlx_now().
   Providing this function here is wrong. */
void curlx_now_init(void)
{
  if(curlx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
                                  VERSION_GREATER_THAN_EQUAL))
    Curl_isVistaOrGreater = true;
  else
    Curl_isVistaOrGreater = false;

  QueryPerformanceFrequency(&Curl_freq);
}

/* In case of bug fix this function has a counterpart in tool_util.c */
struct curltime curlx_now(void)
{
  struct curltime now;
  bool isVistaOrGreater;
  isVistaOrGreater = Curl_isVistaOrGreater;
  if(isVistaOrGreater) { /* QPC timer might have issues pre-Vista */
    LARGE_INTEGER count;
    LARGE_INTEGER freq;
    freq = Curl_freq;
    DEBUGASSERT(freq.QuadPart);
    QueryPerformanceCounter(&count);
    now.tv_sec = (time_t)(count.QuadPart / freq.QuadPart);
    now.tv_usec = (int)((count.QuadPart % freq.QuadPart) * 1000000 /
                        freq.QuadPart);
  }
  else {
    /* Disable /analyze warning that GetTickCount64 is preferred  */
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:28159)
#endif
    DWORD milliseconds = GetTickCount();
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    now.tv_sec = (time_t)(milliseconds / 1000);
    now.tv_usec = (int)((milliseconds % 1000) * 1000);
  }
  return now;
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC) ||  \
  defined(HAVE_CLOCK_GETTIME_MONOTONIC_RAW)

struct curltime curlx_now(void)
{
  /*
  ** clock_gettime() is granted to be increased monotonically when the
  ** monotonic clock is queried. Time starting point is unspecified, it
  ** could be the system start-up time, the Epoch, or something else,
  ** in any case the time starting point does not change once that the
  ** system has started up.
  */
#ifdef HAVE_GETTIMEOFDAY
  struct timeval now;
#endif
  struct curltime cnow;
  struct timespec tsnow;

  /*
  ** clock_gettime() may be defined by Apple's SDK as weak symbol thus
  ** code compiles but fails during runtime if clock_gettime() is
  ** called on unsupported OS version.
  */
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
        (HAVE_BUILTIN_AVAILABLE == 1)
  bool have_clock_gettime = FALSE;
  if(__builtin_available(macOS 10.12, iOS 10, tvOS 10, watchOS 3, *))
    have_clock_gettime = TRUE;
#endif

#ifdef HAVE_CLOCK_GETTIME_MONOTONIC_RAW
  if(
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) &&    \
        (HAVE_BUILTIN_AVAILABLE == 1)
    have_clock_gettime &&
#endif
    (0 == clock_gettime(CLOCK_MONOTONIC_RAW, &tsnow))) {
    cnow.tv_sec = tsnow.tv_sec;
    cnow.tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  else
#endif

  if(
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
        (HAVE_BUILTIN_AVAILABLE == 1)
    have_clock_gettime &&
#endif
    (0 == clock_gettime(CLOCK_MONOTONIC, &tsnow))) {
    cnow.tv_sec = tsnow.tv_sec;
    cnow.tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  /*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** runtime. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
  else {
    (void)gettimeofday(&now, NULL);
    cnow.tv_sec = now.tv_sec;
    cnow.tv_usec = (int)now.tv_usec;
  }
#else
  else {
    cnow.tv_sec = time(NULL);
    cnow.tv_usec = 0;
  }
#endif
  return cnow;
}

#elif defined(HAVE_MACH_ABSOLUTE_TIME)

#include <stdint.h>
#include <mach/mach_time.h>

struct curltime curlx_now(void)
{
  /*
  ** Monotonic timer on macOS is provided by mach_absolute_time(), which
  ** returns time in Mach "absolute time units," which are platform-dependent.
  ** To convert to nanoseconds, one must use conversion factors specified by
  ** mach_timebase_info().
  */
  static mach_timebase_info_data_t timebase;
  struct curltime cnow;
  uint64_t usecs;

  if(0 == timebase.denom)
    (void) mach_timebase_info(&timebase);

  usecs = mach_absolute_time();
  usecs *= timebase.numer;
  usecs /= timebase.denom;
  usecs /= 1000;

  cnow.tv_sec = usecs / 1000000;
  cnow.tv_usec = (int)(usecs % 1000000);

  return cnow;
}

#elif defined(HAVE_GETTIMEOFDAY)

struct curltime curlx_now(void)
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
  ret.tv_usec = (int)now.tv_usec;
  return ret;
}

#else

struct curltime curlx_now(void)
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
 * Returns: time difference in number of milliseconds. For too large diffs it
 * returns max value.
 *
 * @unittest: 1323
 */
timediff_t curlx_timediff(struct curltime newer, struct curltime older)
{
  timediff_t diff = (timediff_t)newer.tv_sec-older.tv_sec;
  if(diff >= (TIMEDIFF_T_MAX/1000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN/1000))
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec-older.tv_usec)/1000;
}

/*
 * Returns: time difference in number of milliseconds, rounded up.
 * For too large diffs it returns max value.
 */
timediff_t curlx_timediff_ceil(struct curltime newer, struct curltime older)
{
  timediff_t diff = (timediff_t)newer.tv_sec-older.tv_sec;
  if(diff >= (TIMEDIFF_T_MAX/1000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN/1000))
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec - older.tv_usec + 999)/1000;
}

/*
 * Returns: time difference in number of microseconds. For too large diffs it
 * returns max value.
 */
timediff_t curlx_timediff_us(struct curltime newer, struct curltime older)
{
  timediff_t diff = (timediff_t)newer.tv_sec-older.tv_sec;
  if(diff >= (TIMEDIFF_T_MAX/1000000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN/1000000))
    return TIMEDIFF_T_MIN;
  return diff * 1000000 + newer.tv_usec-older.tv_usec;
}
