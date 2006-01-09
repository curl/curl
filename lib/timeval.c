/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "timeval.h"

#ifndef HAVE_GETTIMEOFDAY

#ifdef WIN32
#include <mmsystem.h>

static int gettimeofday(struct timeval *tp, void *nothing)
{
#ifdef WITHOUT_MM_LIB
  SYSTEMTIME st;
  time_t tt;
  struct tm tmtm;
  /* mktime converts local to UTC */
  GetLocalTime (&st);
  tmtm.tm_sec = st.wSecond;
  tmtm.tm_min = st.wMinute;
  tmtm.tm_hour = st.wHour;
  tmtm.tm_mday = st.wDay;
  tmtm.tm_mon = st.wMonth - 1;
  tmtm.tm_year = st.wYear - 1900;
  tmtm.tm_isdst = -1;
  tt = mktime (&tmtm);
  tp->tv_sec = tt;
  tp->tv_usec = st.wMilliseconds * 1000;
#else
  /**
   ** The earlier time calculations using GetLocalTime
   ** had a time resolution of 10ms.The timeGetTime, part
   ** of multimedia apis offer a better time resolution
   ** of 1ms.Need to link against winmm.lib for this
   **/
  unsigned long Ticks = 0;
  unsigned long Sec =0;
  unsigned long Usec = 0;
  Ticks = timeGetTime();

  Sec = Ticks/1000;
  Usec = (Ticks - (Sec*1000))*1000;
  tp->tv_sec = Sec;
  tp->tv_usec = Usec;
#endif /* WITHOUT_MM_LIB */
  (void)nothing;
  return 0;
}
#else /* WIN32 */
/* non-win32 version of Curl_gettimeofday() */
static int gettimeofday(struct timeval *tp, void *nothing)
{
  (void)nothing; /* we don't support specific time-zones */
  tp->tv_sec = (long)time(NULL);
  tp->tv_usec = 0;
  return 0;
}
#endif /* WIN32 */
#endif /* HAVE_GETTIMEOFDAY */

/* Return the current time in a timeval struct */
struct timeval curlx_tvnow(void)
{
  struct timeval now;
  (void)gettimeofday(&now, NULL);
  return now;
}

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we'll get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
long curlx_tvdiff(struct timeval newer, struct timeval older)
{
  return (newer.tv_sec-older.tv_sec)*1000+
    (newer.tv_usec-older.tv_usec)/1000;
}

/*
 * Same as curlx_tvdiff but with full usec resolution.
 *
 * Returns: the time difference in seconds with subsecond resolution.
 */
double curlx_tvdiff_secs(struct timeval newer, struct timeval older)
{
  return (double)(newer.tv_sec-older.tv_sec)+
    (double)(newer.tv_usec-older.tv_usec)/1000000.0;
}

/* return the number of seconds in the given input timeval struct */
long Curl_tvlong(struct timeval t1)
{
  return t1.tv_sec;
}
