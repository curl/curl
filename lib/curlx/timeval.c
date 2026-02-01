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

#include "../system_win32.h"

LARGE_INTEGER Curl_freq;

/* For tool or tests, we must initialize before calling curlx_now().
   Providing this function here is wrong. */
void curlx_now_init(void)
{
  QueryPerformanceFrequency(&Curl_freq);
}

/* In case of bug fix this function has a counterpart in tool_util.c */
void curlx_pnow(struct curltime *pnow)
{
  LARGE_INTEGER count;
  DEBUGASSERT(Curl_freq.QuadPart);
  QueryPerformanceCounter(&count);
  pnow->tv_sec = (time_t)(count.QuadPart / Curl_freq.QuadPart);
  pnow->tv_usec = (int)((count.QuadPart % Curl_freq.QuadPart) * 1000000 /
                        Curl_freq.QuadPart);
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC) || \
  defined(HAVE_CLOCK_GETTIME_MONOTONIC_RAW)

void curlx_pnow(struct curltime *pnow)
{
  /*
   * clock_gettime() is granted to be increased monotonically when the
   * monotonic clock is queried. Time starting point is unspecified, it
   * could be the system start-up time, the Epoch, or something else,
   * in any case the time starting point does not change once that the
   * system has started up.
   */
  struct timespec tsnow;

  /*
   * clock_gettime() may be defined by Apple's SDK as weak symbol thus
   * code compiles but fails during runtime if clock_gettime() is
   * called on unsupported OS version.
   */
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
  (HAVE_BUILTIN_AVAILABLE == 1)
  bool have_clock_gettime = FALSE;
  if(__builtin_available(macOS 10.12, iOS 10, tvOS 10, watchOS 3, *))
    have_clock_gettime = TRUE;
#endif

#ifdef HAVE_CLOCK_GETTIME_MONOTONIC_RAW
  if(
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
  (HAVE_BUILTIN_AVAILABLE == 1)
    have_clock_gettime &&
#endif
    (clock_gettime(CLOCK_MONOTONIC_RAW, &tsnow) == 0)) {
    pnow->tv_sec = tsnow.tv_sec;
    pnow->tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  else
#endif

  if(
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
  (HAVE_BUILTIN_AVAILABLE == 1)
    have_clock_gettime &&
#endif
    (clock_gettime(CLOCK_MONOTONIC, &tsnow) == 0)) {
    pnow->tv_sec = tsnow.tv_sec;
    pnow->tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  /*
   * Even when the configure process has truly detected monotonic clock
   * availability, it might happen that it is not actually available at
   * runtime. When this occurs simply fallback to other time source.
   */
#ifdef HAVE_GETTIMEOFDAY
  else {
    struct timeval now;
    (void)gettimeofday(&now, NULL);
    pnow->tv_sec = now.tv_sec;
    pnow->tv_usec = (int)now.tv_usec;
  }
#else
  else {
    pnow->tv_sec = time(NULL);
    pnow->tv_usec = 0;
  }
#endif
}

#elif defined(HAVE_MACH_ABSOLUTE_TIME)

#include <mach/mach_time.h>

void curlx_pnow(struct curltime *pnow)
{
  /*
   * Monotonic timer on macOS is provided by mach_absolute_time(), which
   * returns time in Mach "absolute time units," which are platform-dependent.
   * To convert to nanoseconds, one must use conversion factors specified by
   * mach_timebase_info().
   */
  static mach_timebase_info_data_t timebase;
  uint64_t usecs;

  if(timebase.denom == 0)
    (void)mach_timebase_info(&timebase);

  usecs = mach_absolute_time();
  usecs *= timebase.numer; /* spellchecker:disable-line */
  usecs /= timebase.denom;
  usecs /= 1000;

  pnow->tv_sec = usecs / 1000000;
  pnow->tv_usec = (int)(usecs % 1000000);
}

#elif defined(HAVE_GETTIMEOFDAY)

void curlx_pnow(struct curltime *pnow)
{
  /*
   * gettimeofday() is not granted to be increased monotonically, due to
   * clock drifting and external source time synchronization it can jump
   * forward or backward in time.
   */
  struct timeval now;
  (void)gettimeofday(&now, NULL);
  pnow->tv_sec = now.tv_sec;
  pnow->tv_usec = (int)now.tv_usec;
}

#else

void curlx_pnow(struct curltime *pnow)
{
  /*
   * time() returns the value of time in seconds since the Epoch.
   */
  pnow->tv_sec = time(NULL);
  pnow->tv_usec = 0;
}

#endif

struct curltime curlx_now(void)
{
  struct curltime now;
  curlx_pnow(&now);
  return now;
}

/*
 * Returns: time difference in number of milliseconds. For too large diffs it
 * returns max value.
 *
 * @unittest: 1323
 */
timediff_t curlx_ptimediff_ms(const struct curltime *newer,
                              const struct curltime *older)
{
  timediff_t diff = (timediff_t)newer->tv_sec - older->tv_sec;
  if(diff >= (TIMEDIFF_T_MAX / 1000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN / 1000))
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer->tv_usec - older->tv_usec) / 1000;
}


timediff_t curlx_timediff_ms(struct curltime newer, struct curltime older)
{
  return curlx_ptimediff_ms(&newer, &older);
}

/*
 * Returns: time difference in number of milliseconds, rounded up.
 * For too large diffs it returns max value.
 */
timediff_t curlx_timediff_ceil_ms(struct curltime newer,
                                  struct curltime older)
{
  timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
  if(diff >= (TIMEDIFF_T_MAX / 1000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN / 1000))
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec - older.tv_usec + 999) / 1000;
}

/*
 * Returns: time difference in number of microseconds. For too large diffs it
 * returns max value.
 */
timediff_t curlx_ptimediff_us(const struct curltime *newer,
                              const struct curltime *older)
{
  timediff_t diff = (timediff_t)newer->tv_sec - older->tv_sec;
  if(diff >= (TIMEDIFF_T_MAX / 1000000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN / 1000000))
    return TIMEDIFF_T_MIN;
  return diff * 1000000 + newer->tv_usec - older->tv_usec;
}

timediff_t curlx_timediff_us(struct curltime newer, struct curltime older)
{
  return curlx_ptimediff_us(&newer, &older);
}

#if defined(__MINGW32__) && (__MINGW64_VERSION_MAJOR <= 3)
#include <sec_api/time_s.h>  /* for _gmtime32_s(), _gmtime64_s() */
#ifdef _USE_32BIT_TIME_T
#define gmtime_s _gmtime32_s
#else
#define gmtime_s _gmtime64_s
#endif
#endif

/*
 * curlx_gmtime() is a gmtime() replacement for portability. Do not use
 * the gmtime_s(), gmtime_r() or gmtime() functions anywhere else but here.
 */
CURLcode curlx_gmtime(time_t intime, struct tm *store)
{
#ifdef _WIN32
  if(gmtime_s(store, &intime)) /* thread-safe */
    return CURLE_BAD_FUNCTION_ARGUMENT;
#elif defined(HAVE_GMTIME_R)
  const struct tm *tm;
  tm = gmtime_r(&intime, store); /* thread-safe */
  if(!tm)
    return CURLE_BAD_FUNCTION_ARGUMENT;
#else
  const struct tm *tm;
  /* !checksrc! disable BANNEDFUNC 1 */
  tm = gmtime(&intime); /* not thread-safe */
  if(tm)
    *store = *tm; /* copy the pointed struct to the local copy */
  else
    return CURLE_BAD_FUNCTION_ARGUMENT;
#endif

  return CURLE_OK;
}
