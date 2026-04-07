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

static CURLcode test_lib517(const char *URL)
{
  struct dcheck {
    const char *input;
    time_t output;
  };

  static const struct dcheck dates[] = {
    { "Sun, 06 Nov 1994 08:49:37 GMT", 784111777 },
    { "Sunday, 06-Nov-94 08:49:37 GMT", 784111777 },
    { "Sun Nov  6 08:49:37 1994", 784111777 },
    { "Sun Nov  6 8:49:37 1994", 784111777 },
    { "Sun Nov  6 8:9:37 1994", 784109377 },
    { "Sun Nov  6 008:09:37 1994", -1 },
    { "Nov      Sun      6 8:9:7 1994", 784109347 },
    { "06 Nov 1994 08:49:37 GMT", 784111777 },
    { "06-Nov-94 08:49:37 GMT", 784111777 },
    { "Nov  6 08:49:37 1994", 784111777 },
    { "06 Nov 1994 08:49:37", 784111777 },
    { "06-Nov-94 08:49:37", 784111777 },
    { "1994 Nov 6 08:49:37", 784111777 },
    { "GMT 08:49:37 06-Nov-94 Sunday", 784111777 },
    { "94 6 Nov 08:49:37", 784111777 },
    { "1994 Nov 6", 784080000 },
    { "06-Nov-94", 784080000 },
    { "Sun Nov 6 94", 784080000 },
    { "1994.Nov.6", 784080000 },
    { "Sun/Nov/6/94/GMT", 784080000 },
    { "Sun, 06 Nov 1994 08:49:37 CET", 784108177 },
    { "06 Nov 1994 08:49:37 EST", 784129777 },
    { "Sun, 06 Nov 1994 08:49:37 UT", 784111777 },
    { "Sun, 12 Sep 2004 15:05:58 -0700", 1095026758 },
    { "Sat, 11 Sep 2004 21:32:11 +0200", 1094931131 },
    { "20040912 15:05:58 -0700", 1095026758 },
    { "20040911 +0200", 1094853600 },
    { "Thu, 01-Jan-1970 00:59:59 GMT", 3599 },
    { "Thu, 01-Jan-1970 01:00:00 GMT", 3600 },
    { "Sat, 15-Apr-17 21:01:22 GMT", 1492290082 },
    { "Thu, 19-Apr-2007 16:00:00 GMT", 1176998400 },
    { "Wed, 25 Apr 2007 21:02:13 GMT", 1177534933 },
    { "Thu, 19/Apr\\2007 16:00:00 GMT", 1176998400 },
    { "Fri, 1 Jan 2010 01:01:50 GMT", 1262307710 },
    { "Wednesday, 1-Jan-2003 00:00:00 GMT", 1041379200 },
    { ", 1-Jan-2003 00:00:00 GMT", 1041379200 },
    { "1-Jan-2003 00:00:00 GMT", 1041379200 },
    { "1-Jan-2003 00:00:00 GMT", 1041379200 },
    { "Wed,18-Apr-07 22:50:12 GMT", 1176936612 },
    { "WillyWonka  , 18-Apr-07 22:50:12 GMT", -1 },
    { "WillyWonka  , 18-Apr-07 22:50:12", -1 },
    { "WillyWonka  ,  18-apr-07   22:50:12", -1 },
    { "Mon, 18-Apr-1977 22:50:13 GMT", 230251813 },
    { "Mon, 18-Apr-77 22:50:13 GMT", 230251813 },
    { "Sat, 15-Apr-17\"21:01:22\"GMT", 1492290082 },
    { "Partyday, 18- April-07 22:50:12", -1 },
    { "Partyday, 18 - Apri-07 22:50:12", -1 },
    { "Wednes, 1-Januar-2003 00:00:00 GMT", -1 },
    { "Sat, 15-Apr-17 21:01:22", 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT-2", 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT BLAH", 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT-0400", 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)", 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 DST", -1 },
    { "Sat, 15-Apr-17 21:01:22 -0400", 1492304482 },
    { "Sat, 15-Apr-17 21:01:22 (hello there)", -1 },
    { "Sat, 15-Apr-17 21:01:22 11:22:33", -1 },
    { "Sat, 15-Apr-17 ::00 21:01:22", -1 },
    { "Sat, 15-Apr-17 boink:z 21:01:22", -1 },
    { "Sat, 15-Apr-17 91:22:33 21:01:22", -1 },
    { "Thu Apr 18 22:50:12 2007 GMT", 1176936612 },
    { "22:50:12 Thu Apr 18 2007 GMT", 1176936612 },
    { "Thu 22:50:12 Apr 18 2007 GMT", 1176936612 },
    { "Thu Apr 22:50:12 18 2007 GMT", 1176936612 },
    { "Thu Apr 18 22:50:12 2007 GMT", 1176936612 },
    { "Thu Apr 18 2007 22:50:12 GMT", 1176936612 },
    { "Thu Apr 18 2007 GMT 22:50:12", 1176936612 },

    { "\"Thu Apr 18 22:50:12 2007 GMT\"", 1176936612 },
    { "-\"22:50:12 Thu Apr 18 2007 GMT\"", 1176936612 },
    { "*\"Thu 22:50:12 Apr 18 2007 GMT\"", 1176936612 },
    { ";\"Thu Apr 22:50:12 18 2007 GMT\"", 1176936612 },
    { ".\"Thu Apr 18 22:50:12 2007 GMT\"", 1176936612 },
    { "\"Thu Apr 18 2007 22:50:12 GMT\"", 1176936612 },
    { "\"Thu Apr 18 2007 GMT 22:50:12\"", 1176936612 },

    { "Sat, 15-Apr-17 21:01:22 GMT", 1492290082 },
    { "15-Sat, Apr-17 21:01:22 GMT", 1492290082 },
    { "15-Sat, Apr 21:01:22 GMT 17", 1492290082 },
    { "15-Sat, Apr 21:01:22 GMT 2017", 1492290082 },
    { "15 Apr 21:01:22 2017", 1492290082 },
    { "15 17 Apr 21:01:22", 1492290082 },
    { "Apr 15 17 21:01:22", 1492290082 },
    { "Apr 15 21:01:22 17", 1492290082 },
    { "2017 April 15 21:01:22", -1 },
    { "15 April 2017 21:01:22", -1 },
    { "98 April 17 21:01:22", -1 },
    { "Thu, 012-Aug-2008 20:49:07 GMT", 1218574147 },
    { "Thu, 999999999999-Aug-2007 20:49:07 GMT", -1 },
    { "Thu, 12-Aug-2007 20:61:99999999999 GMT", -1 },
    { "IAintNoDateFool", -1 },
    { "Thu Apr 18 22:50 2007 GMT", 1176936600 },
    { "20110623 12:34:56", 1308832496 },
    { "20110632 12:34:56", -1 },
    { "20110623 56:34:56", -1 },
    { "20111323 12:34:56", -1 },
    { "20110623 12:34:79", -1 },
    { "Wed, 31 Dec 2008 23:59:60 GMT", 1230768000 },
    { "Wed, 31 Dec 2008 23:59:61 GMT", -1 },
    { "Wed, 31 Dec 2008 24:00:00 GMT", -1 },
    { "Wed, 31 Dec 2008 23:60:59 GMT", -1 },
    { "20110623 12:3", 1308830580 },
    { "20110623 1:3", 1308790980 },
    { "20110623 1:30", 1308792600 },
    { "20110623 12:12:3", 1308831123 },
    { "20110623 01:12:3", 1308791523 },
    { "20110623 01:99:30", -1 },
    { "Thu, 01-Jan-1970 00:00:00 GMT", 0 },
    { "Thu, 31-Dec-1969 23:59:58 GMT", -2 },
    { "Thu, 31-Dec-1969 23:59:59 GMT", 0 }, /* avoids -1 ! */
#if SIZEOF_TIME_T > 4
    { "Sun, 06 Nov 2044 08:49:37 GMT", (time_t)2362034977LL },
    { "Sun, 06 Nov 3144 08:49:37 GMT", 37074617377 },
#ifndef HAVE_TIME_T_UNSIGNED
    { "Sun, 06 Nov 1900 08:49:37 GMT", (time_t)-2182259423LL },
    { "Sun, 06 Nov 1800 08:49:37 GMT", -5337933023 },
    { "Thu, 01-Jan-1583 00:00:00 GMT", -12212553600 },
#endif /* HAVE_TIME_T_UNSIGNED */
    { "Thu, 01-Jan-1499 00:00:00 GMT", -1 },
#else
    { "Sun, 06 Nov 2044 08:49:37 GMT", -1 },
#endif /* SIZEOF_TIME_T > 4 */
#ifndef HAVE_TIME_T_UNSIGNED
    { "Sun, 06 Nov 1968 08:49:37 GMT", -36342623 },
#endif /* !HAVE_TIME_T_UNSIGNED */

#if SIZEOF_TIME_T > 4
    { "2094 Nov 6 08:49:37", 3939871777 },
#endif
    { "01 Jan 2001 8:0:0", 978336000},
    { "01 Jan 2001 8:00:0", 978336000},
    /* Out-of-range day-of-month Cases */
    { "29 Feb 2023 12:00:00 GMT", 1677672000},
    { "31 Apr 2024 12:00:00 GMT", 1714564800},
    { "30 Feb 2024 12:00:00 GMT", 1709294400},
    { "01-13-2024", -1},
    { "32 Jan 2024", -1},
    { "31 Jan 2024", 1706659200},
    { "32 Feb 2024", -1},
    { "32 Mar 2024", -1},
    { "32 Apr 2024", -1},
    { "32 May 2024", -1},
    { "32 Jun 2024", -1},
    { "32 Jul 2024", -1},
    { "32 Aug 2024", -1},
    { "32 Sep 2024", -1},
    { "32 Oct 2024", -1},
    { "32 Nov 2024", -1},
    { "32 Dec 2024", -1},
    /* Timezone Offsets */
    { "Sun, 06 Nov 1994 08:49:37 +0530", 784091977 },
    { "Sun, 06 Nov 1994 08:49:37 +0545", 784091077 },
    { "06 Nov 1994 08:49:37 Z", 784111777 },
    { "06 Nov 1994 08:49:37 T", 784086577 },
    { "GMT+05:30", -1 },
    { "GMT-08:00", -1 },
    /* ISO 8601 & Variations - not supported */
    { "1994-11-06T08:49:37Z", -1 },
    { "1994-11-06 08:49:37.123 GMT", -1 },
    { "19941106T084937Z", -1 },
    /* Y2K38 & Historical Boundaries */
#if SIZEOF_TIME_T > 4
    /* for 32 bit time_t, we bail on >year 2037 */
    { "19 Jan 2038 03:14:07 GMT", 2147483647},
    { "19 Jan 2038 03:14:08 GMT", 2147483648},
    { "01 Jan 69 00:00:00 GMT", 3124224000},
#endif
    { "01 Jan 1500 00:00:00 GMT", -1},
    /* Formatting & Malformed Junk */
    { "Sun, 06-Nov/1994 08:49:37", 784111777},
    { "Sun,    06 Nov   1994   08:49:37 GMT", 784111777},
    { "  Sun, 06 Nov 1994 08:49:37 GMT  ", 784111777},
    { "Date: Sun, 06 Nov 1994 08:49:37 GMT", -1},
    /* wrong day name is ignored */
    { "Monday, 06 Nov 1994 08:49:37 GMT", 784111777},
    { NULL, 0 }
  };

  int i;
  int error = 0;

  (void)URL;

  for(i = 0; dates[i].input; i++) {
    time_t out = curl_getdate(dates[i].input, NULL);
    if(out != dates[i].output) {
      curl_mprintf("WRONGLY %s => %" CURL_FORMAT_CURL_OFF_T
                   " (instead of %" CURL_FORMAT_CURL_OFF_T ")\n",
                   dates[i].input,
                   (curl_off_t)out, (curl_off_t)dates[i].output);
      error++;
    }
  }

  return error == 0 ? CURLE_OK : TEST_ERR_FAILURE;
}
