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
#include "first.h"

static const char *dates[] = {
  "Sun, 06 Nov 1994 08:49:37 GMT",
  "Sunday, 06-Nov-94 08:49:37 GMT",
  "Sun Nov  6 08:49:37 1994",
  "Sun Nov  6 8:49:37 1994",
  "Sun Nov  6 8:9:37 1994",
  "Sun Nov  6 008:09:37 1994",
  "Nov      Sun      6 8:9:7 1994",
  "06 Nov 1994 08:49:37 GMT",
  "06-Nov-94 08:49:37 GMT",
  "Nov  6 08:49:37 1994",
  "06 Nov 1994 08:49:37",
  "06-Nov-94 08:49:37",
  "1994 Nov 6 08:49:37",
  "GMT 08:49:37 06-Nov-94 Sunday",
  "94 6 Nov 08:49:37",
  "1994 Nov 6",
  "06-Nov-94",
  "Sun Nov 6 94",
  "1994.Nov.6",
  "Sun/Nov/6/94/GMT",
  "Sun, 06 Nov 1994 08:49:37 CET",
  "Sun, 06 Nov 1994 08:49:37 cet",
  "Sun, 06 Nov 1994 08:49:37 utc",
  "Sun, 06 Nov 1994 08:49:37 gmt",
  "06 Nov 1994 08:49:37 EST",
  "Sun, 06 Nov 1994 08:49:37 UT",
  "Sun, 12 Sep 2004 15:05:58 -0700",
  "Sat, 11 Sep 2004 21:32:11 +0200",
  "20040912 15:05:58 -0700",
  "20040911 +0200",
  "Thu, 01-Jan-1970 00:59:59 GMT",
  "Thu, 01-Jan-1970 01:00:00 GMT",
  "Sat, 15-Apr-17 21:01:22 GMT",
  "Thu, 19-Apr-2007 16:00:00 GMT",
  "Wed, 25 Apr 2007 21:02:13 GMT",
  "Thu, 19/Apr\\2007 16:00:00 GMT",
  "Fri, 1 Jan 2010 01:01:50 GMT",
  "Wednesday, 1-Jan-2003 00:00:00 GMT",
  "",
  "-",
  "a",
  "1-Jan-2003 00:00:00 GMT",
  "1-Jan-2003 00:00:00 GMT",
  "Wed,18-Apr-07 22:50:12 GMT",
  "BillyWonka  , 18-Apr-07 22:50:12 GMT",
  "BillyWonka  , 18-Apr-07 22:50:12",
  "BillyWonka  ,  18-apr-07   22:50:12",
  "Mon, 18-Apr-1977 22:50:13 GMT",
  "Mon, 18-Apr-77 22:50:13 GMT",
  "Sat, 15-Apr-17\"21:01:22\"GMT",
  "Partyday, 18- April-07 22:50:12",
  "Partyday, 18 - Apri-07 22:50:12",
  "Wednes, 1-Januar-2003 00:00:00 GMT",
  "Sat, 15-Apr-17 21:01:22",
  "Sat, 15-Apr-17 21:01:22 GMT-2",
  "Sat, 15-Apr-17 21:01:22 GMT BLAH",
  "Sat, 15-Apr-17 21:01:22 GMT-0400",
  "Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)",
  "Sat, 15-Apr-17 21:01:22 DST",
  "Sat, 15-Apr-17 21:01:22 -0400",
  "Sat, 15-Apr-17 21:01:22 (hello there)",
  "Sat, 15-Apr-17 21:01:22 11:22:33",
  "Sat, 15-Apr-17 ::00 21:01:22",
  "Sat, 15-Apr-17 boink:z 21:01:22",
  "Sat, 15-Apr-17 91:22:33 21:01:22",
  "Thu Apr 18 22:50:12 2007 GMT",
  "22:50:12 Thu Apr 18 2007 GMT",
  "Thu 22:50:12 Apr 18 2007 GMT",
  "Thu Apr 22:50:12 18 2007 GMT",
  "Thu Apr 18 22:50:12 2007 GMT",
  "Thu Apr 18 2007 22:50:12 GMT",
  "Thu Apr 18 2007 GMT 22:50:12",
  "\"Thu Apr 18 22:50:12 2007 GMT\"",
  "-\"22:50:12 Thu Apr 18 2007 GMT\"",
  "*\"Thu 22:50:12 Apr 18 2007 GMT\"",
  ";\"Thu Apr 22:50:12 18 2007 GMT\"",
  ".\"Thu Apr 18 22:50:12 2007 GMT\"",
  "\"Thu Apr 18 2007 22:50:12 GMT\"",
  "\"Thu Apr 18 2007 GMT 22:50:12\"",
  "Sat, 15-Apr-17 21:01:22 GMT",
  "15-Sat, Apr-17 21:01:22 GMT",
  "15-Sat, Apr 21:01:22 GMT 17",
  "15-Sat, Apr 21:01:22 GMT 2017",
  "15 Apr 21:01:22 2017",
  "15 17 Apr 21:01:22",
  "Apr 15 17 21:01:22",
  "Apr 15 21:01:22 17",
  "2017 April 15 21:01:22",
  "15 April 2017 21:01:22",
  "98 April 17 21:01:22",
  "Thu, 012-Aug-2008 20:49:07 GMT",
  "Thu, 999999999999-Aug-2007 20:49:07 GMT",
  "Thu, 12-Aug-2007 20:61:99999999999 GMT",
  "IAintNoDateFool",
  "Thu Apr 18 22:50 2007 GMT",
  "20110623 12:34:56",
  "20110023 12:34:56",
  "20110632 12:34:56",
  "20110623 56:34:56",
  "20111323 12:34:56",
  "20110623 12:34:79",
  "Wed, 31 Dec 2008 23:59:60 GMT",
  "Wed, 31 Dec 2008 23:59:61 GMT",
  "Wed, 31 Dec 2008 24:00:00 GMT",
  "Wed, 31 Dec 2008 23:60:59 GMT",
  "20110623 12:3",
  "20110623 1:3",
  "20110623 1:30",
  "20110623 12:12:3",
  "20110623 01:12:3",
  "20110623 01:99:30",
  "Thu, 01-Jan-1970 00:00:00 GMT",
  "Thu, 31-Dec-1969 23:59:58 GMT",
  "Thu, 31-Dec-1969 23:59:59 GMT",
  "Sun, 06 Nov 2044 08:49:37 GMT",
  "Sun, 06 Nov 3144 08:49:37 GMT",
  "Sun, 06 Nov 1900 08:49:37 GMT",
  "Sun, 06 Nov 1800 08:49:37 GMT",
  "Thu, 01-Jan-1583 00:00:00 GMT",
  "Thu, 01-Jan-1499 00:00:00 GMT",
  "Sun, 06 Nov 1968 08:49:37 GMT",
  "2094 Nov 6 08:49:37",
  "01 Jan 2001 8:0:0",
  "01 Jan 2001 8:00:0",
  /* Out-of-range day-of-month Cases */
  "29 Feb 2023 12:00:00 GMT",
  "31 Apr 2024 12:00:00 GMT",
  "30 Feb 2024 12:00:00 GMT",
  "01-13-2024",
  "32 Jan 2024",
  "31 Jan 2024",
  "32 Feb 2024",
  "32 Mar 2024",
  "32 Apr 2024",
  "32 May 2024",
  "32 Jun 2024",
  "32 Jul 2024",
  "32 Aug 2024",
  "32 Sep 2024",
  "32 Oct 2024",
  "32 Nov 2024",
  "32 Dec 2024",
  /* Timezone Offsets */
  "Sun, 06 Nov 1994 08:49:37 +0530",
  "Sun, 06 Nov 1994 08:49:37 +0545",
  "06 Nov 1994 08:49:37 Z",
  "06 Nov 1994 08:49:37 A",
  "06 Nov 1994 08:49:37 B",
  "06 Nov 1994 08:49:37 C",
  "06 Nov 1994 08:49:37 D",
  "06 Nov 1994 08:49:37 E",
  "06 Nov 1994 08:49:37 F",
  "06 Nov 1994 08:49:37 G",
  "06 Nov 1994 08:49:37 H",
  "06 Nov 1994 08:49:37 I",
  "06 Nov 1994 08:49:37 J",
  "06 Nov 1994 08:49:37 K",
  "06 Nov 1994 08:49:37 L",
  "06 Nov 1994 08:49:37 M",
  "06 Nov 1994 08:49:37 N",
  "06 Nov 1994 08:49:37 O",
  "06 Nov 1994 08:49:37 P",
  "06 Nov 1994 08:49:37 Q",
  "06 Nov 1994 08:49:37 R",
  "06 Nov 1994 08:49:37 S",
  "06 Nov 1994 08:49:37 T",
  "06 Nov 1994 08:49:37 U",
  "06 Nov 1994 08:49:37 V",
  "06 Nov 1994 08:49:37 W",
  "06 Nov 1994 08:49:37 X",
  "06 Nov 1994 08:49:37 Y",
  "GMT+05:30",
  "GMT-08:00",
  /* ISO 8601 & Variations - not supported */
  "1994-11-06T08:49:37Z",
  "1994-11-06 08:49:37.123 GMT",
  "19941106T084937Z",
  /* Y2K38 & Historical Boundaries */
  "19 Jan 2038 03:14:07 GMT",
  "19 Jan 2038 03:14:08 GMT",
  "01 Jan 69 00:00:00 GMT",
  "01 Jan 1500 00:00:00 GMT",
  /* Formatting & Malformed Junk */
  "Sun, 06-Nov/1994 08:49:37",
  "Sun,    06 Nov   1994   08:49:37 GMT",
  "  Sun, 06 Nov 1994 08:49:37 GMT  ",
  "Date: Sun, 06 Nov 1994 08:49:37 GMT",
  /* wrong day name is ignored */
  "Monday, 06 Nov 1994 08:49:37 GMT"
};

/*
 * Parse the dates
 */
static int test_dateparser(int argc, const char **argv)
{
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;
  curl_off_t loops = 100000, loop;
  curl_off_t count = 0;
  curl_off_t ecount = 0; /* errors */
  size_t i;
  size_t ndates = CURL_ARRAYSIZE(dates);

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, INT_MAX) && !*ptr)
      loops = num;
  }

  curl_mprintf("Found %zu dates to test\n", ndates);

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    for(i = 0; i < ndates; i++) {
      time_t out = curl_getdate(dates[i], NULL);
      count++;
      if(out == (time_t)-1) {
#if 0
        curl_mfprintf(stderr, "Failed [%u]: %s\n", (int)hcode, buffer);
#endif
        ecount++;
      }
    }
  }
  end = curlx_now();
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = count ? us * 100000 / count : 0; /* 100 times too big */
  curl_mprintf("Dates:     %" CURL_FORMAT_CURL_OFF_T "\n"
               "Time:      %lld usecs\n"
               "Time/date: %lld.%02lld ns\n"
               "Dates/sec: %lld\n"
               "Errors:    %" CURL_FORMAT_CURL_OFF_T "\n",
               count,
               (long long)us,
               (long long)hn / 100,
               (long long)hn % 100,
               us ? (long long)(count * 1000000) / us : 0,
               ecount);
  return 0;
}
