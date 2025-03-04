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
#include "tool_setup.h"

#include "tool_util.h"

#include "curlx.h"
#include "memdebug.h" /* keep this as LAST include */

#ifdef _WIN32

/* In case of bug fix this function has a counterpart in timeval.c */
struct timeval tvnow(void)
{
  struct timeval now;
  if(tool_isVistaOrGreater) { /* QPC timer might have issues pre-Vista */
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    now.tv_sec = (long)(count.QuadPart / tool_freq.QuadPart);
    now.tv_usec = (long)((count.QuadPart % tool_freq.QuadPart) * 1000000 /
                         tool_freq.QuadPart);
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

    now.tv_sec = (long)(milliseconds / 1000);
    now.tv_usec = (long)((milliseconds % 1000) * 1000);
  }
  return now;
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC)

struct timeval tvnow(void)
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
    now.tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  /*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** runtime. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
  else
    (void)gettimeofday(&now, NULL);
#else
  else {
    now.tv_sec = time(NULL);
    now.tv_usec = 0;
  }
#endif
  return now;
}

#elif defined(HAVE_GETTIMEOFDAY)

struct timeval tvnow(void)
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

struct timeval tvnow(void)
{
  /*
  ** time() returns the value of time in seconds since the Epoch.
  */
  struct timeval now;
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
  return now;
}

#endif

#ifdef _WIN32

struct timeval tvrealnow(void)
{
  /* UNIX EPOCH (1970-01-01) in FILETIME (1601-01-01) as 64-bit value */
  static const curl_uint64_t EPOCH = (curl_uint64_t)116444736000000000ULL;
  SYSTEMTIME systime;
  FILETIME ftime; /* 100ns since 1601-01-01, as double 32-bit value */
  curl_uint64_t time; /* 100ns since 1601-01-01, as 64-bit value */
  struct timeval now;

  GetSystemTime(&systime);
  SystemTimeToFileTime(&systime, &ftime);
  time = ((curl_uint64_t)ftime.dwLowDateTime);
  time += ((curl_uint64_t)ftime.dwHighDateTime) << 32;

  now.tv_sec  = (long)((time - EPOCH) / 10000000L); /* unit is 100ns */
  now.tv_usec = (long)(systime.wMilliseconds * 1000);
  return now;
}

#else

struct timeval tvrealnow(void)
{
  struct timeval now;
#ifdef HAVE_GETTIMEOFDAY
  (void)gettimeofday(&now, NULL);
#else
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
#endif
  return now;
}

#endif

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we will get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
long tvdiff(struct timeval newer, struct timeval older)
{
  return (long)(newer.tv_sec-older.tv_sec)*1000+
    (long)(newer.tv_usec-older.tv_usec)/1000;
}

/* Case insensitive compare. Accept NULL pointers. */
int struplocompare(const char *p1, const char *p2)
{
  if(!p1)
    return p2 ? -1 : 0;
  if(!p2)
    return 1;
  return CURL_STRICMP(p1, p2);
}

/* Indirect version to use as qsort callback. */
int struplocompare4sort(const void *p1, const void *p2)
{
  return struplocompare(* (char * const *) p1, * (char * const *) p2);
}

#ifdef USE_TOOL_FTRUNCATE

#ifdef UNDER_CE
/* 64-bit lseek-like function unavailable */
#  undef _lseeki64
#  define _lseeki64(hnd,ofs,whence) lseek(hnd,ofs,whence)
#endif

/*
 * Truncate a file handle at a 64-bit position 'where'.
 */

int tool_ftruncate64(int fd, curl_off_t where)
{
  intptr_t handle = _get_osfhandle(fd);

  if(_lseeki64(fd, where, SEEK_SET) < 0)
    return -1;

  if(!SetEndOfFile((HANDLE)handle))
    return -1;

  return 0;
}

#endif /* USE_TOOL_FTRUNCATE */

#if defined(_WIN32) && !defined(UNDER_CE)
FILE *Curl_execpath(const char *filename, char **pathp)
{
  static char filebuffer[512];
  unsigned long len;
  /* Get the filename of our executable. GetModuleFileName is already declared
   * via inclusions done in setup header file. We assume that we are using
   * the ASCII version here.
   */
  len = GetModuleFileNameA(0, filebuffer, sizeof(filebuffer));
  if(len > 0 && len < sizeof(filebuffer)) {
    /* We got a valid filename - get the directory part */
    char *lastdirchar = strrchr(filebuffer, DIR_CHAR[0]);
    if(lastdirchar) {
      size_t remaining;
      *lastdirchar = 0;
      /* If we have enough space, build the RC filename */
      remaining = sizeof(filebuffer) - strlen(filebuffer);
      if(strlen(filename) < remaining - 1) {
        msnprintf(lastdirchar, remaining, "%s%s", DIR_CHAR, filename);
        *pathp = filebuffer;
        return fopen(filebuffer, FOPEN_READTEXT);
      }
    }
  }

  return NULL;
}
#endif
