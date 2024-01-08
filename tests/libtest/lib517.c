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
#include "test.h"

#include "memdebug.h"

struct dcheck {
  const char *input;
  time_t output;
};

static const struct dcheck dates[] = {
  {"Sun, 06 Nov 1994 08:49:37 GMT", 784111777 },
  {"Sunday, 06-Nov-94 08:49:37 GMT", 784111777 },
  {"Sun Nov  6 08:49:37 1994", 784111777 },
  {"Sun Nov  6 8:49:37 1994", 784111777 },
  {"Sun Nov  6 8:9:37 1994", 784109377 },
  {"Sun Nov  6 008:09:37 1994", -1 },
  {"Nov      Sun      6 8:9:7 1994", 784109347 },
  {"06 Nov 1994 08:49:37 GMT", 784111777 },
  {"06-Nov-94 08:49:37 GMT", 784111777 },
  {"Nov  6 08:49:37 1994", 784111777 },
  {"06 Nov 1994 08:49:37", 784111777 },
  {"06-Nov-94 08:49:37", 784111777 },
  {"1994 Nov 6 08:49:37", 784111777 },
  {"GMT 08:49:37 06-Nov-94 Sunday", 784111777 },
  {"94 6 Nov 08:49:37", 784111777 },
  {"1994 Nov 6", 784080000 },
  {"06-Nov-94", 784080000 },
  {"Sun Nov 6 94", 784080000 },
  {"1994.Nov.6", 784080000 },
  {"Sun/Nov/6/94/GMT", 784080000 },
  {"Sun, 06 Nov 1994 08:49:37 CET", 784108177 },
  {"06 Nov 1994 08:49:37 EST", 784129777 },
  {"Sun, 06 Nov 1994 08:49:37 UT", 784111777 },
  {"Sun, 12 Sep 2004 15:05:58 -0700", 1095026758 },
  {"Sat, 11 Sep 2004 21:32:11 +0200", 1094931131 },
  {"20040912 15:05:58 -0700", 1095026758 },
  {"20040911 +0200", 1094853600 },
  {"Thu, 01-Jan-1970 00:59:59 GMT", 3599 },
  {"Thu, 01-Jan-1970 01:00:00 GMT", 3600 },
  {"Sat, 15-Apr-17 21:01:22 GMT", 1492290082 },
  {"Thu, 19-Apr-2007 16:00:00 GMT", 1176998400 },
  {"Wed, 25 Apr 2007 21:02:13 GMT", 1177534933 },
  {"Thu, 19/Apr\\2007 16:00:00 GMT", 1176998400 },
  {"Fri, 1 Jan 2010 01:01:50 GMT", 1262307710 },
  {"Wednesday, 1-Jan-2003 00:00:00 GMT", 1041379200 },
  {", 1-Jan-2003 00:00:00 GMT", 1041379200 },
  {"1-Jan-2003 00:00:00 GMT", 1041379200 },
  {"1-Jan-2003 00:00:00 GMT", 1041379200 },
  {"Wed,18-Apr-07 22:50:12 GMT", 1176936612 },
  {"WillyWonka  , 18-Apr-07 22:50:12 GMT", -1 },
  {"WillyWonka  , 18-Apr-07 22:50:12", -1 },
  {"WillyWonka  ,  18-apr-07   22:50:12", -1 },
  {"Mon, 18-Apr-1977 22:50:13 GMT", 230251813 },
  {"Mon, 18-Apr-77 22:50:13 GMT", 230251813 },
  {"Sat, 15-Apr-17\"21:01:22\"GMT", 1492290082 },
  {"Partyday, 18- April-07 22:50:12", -1 },
  {"Partyday, 18 - Apri-07 22:50:12", -1 },
  {"Wednes, 1-Januar-2003 00:00:00 GMT", -1 },
  {"Sat, 15-Apr-17 21:01:22", 1492290082 },
  {"Sat, 15-Apr-17 21:01:22 GMT-2", 1492290082 },
  {"Sat, 15-Apr-17 21:01:22 GMT BLAH", 1492290082 },
  {"Sat, 15-Apr-17 21:01:22 GMT-0400", 1492290082 },
  {"Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)", 1492290082 },
  {"Sat, 15-Apr-17 21:01:22 DST", -1 },
  {"Sat, 15-Apr-17 21:01:22 -0400", 1492304482 },
  {"Sat, 15-Apr-17 21:01:22 (hello there)", -1 },
  {"Sat, 15-Apr-17 21:01:22 11:22:33", -1 },
  {"Sat, 15-Apr-17 ::00 21:01:22", -1 },
  {"Sat, 15-Apr-17 boink:z 21:01:22", -1 },
  {"Sat, 15-Apr-17 91:22:33 21:01:22", -1 },
  {"Thu Apr 18 22:50:12 2007 GMT", 1176936612 },
  {"22:50:12 Thu Apr 18 2007 GMT", 1176936612 },
  {"Thu 22:50:12 Apr 18 2007 GMT", 1176936612 },
  {"Thu Apr 22:50:12 18 2007 GMT", 1176936612 },
  {"Thu Apr 18 22:50:12 2007 GMT", 1176936612 },
  {"Thu Apr 18 2007 22:50:12 GMT", 1176936612 },
  {"Thu Apr 18 2007 GMT 22:50:12", 1176936612 },
  {"Sat, 15-Apr-17 21:01:22 GMT", 1492290082 },
  {"15-Sat, Apr-17 21:01:22 GMT", 1492290082 },
  {"15-Sat, Apr 21:01:22 GMT 17", 1492290082 },
  {"15-Sat, Apr 21:01:22 GMT 2017", 1492290082 },
  {"15 Apr 21:01:22 2017", 1492290082 },
  {"15 17 Apr 21:01:22", 1492290082 },
  {"Apr 15 17 21:01:22", 1492290082 },
  {"Apr 15 21:01:22 17", 1492290082 },
  {"2017 April 15 21:01:22", -1 },
  {"15 April 2017 21:01:22", -1 },
  {"98 April 17 21:01:22", -1 },
  {"Thu, 012-Aug-2008 20:49:07 GMT", 1218574147 },
  {"Thu, 999999999999-Aug-2007 20:49:07 GMT", -1 },
  {"Thu, 12-Aug-2007 20:61:99999999999 GMT", -1 },
  {"IAintNoDateFool", -1 },
  {"Thu Apr 18 22:50 2007 GMT", 1176936600 },
  {"20110623 12:34:56", 1308832496 },
  {"20110632 12:34:56", -1 },
  {"20110623 56:34:56", -1 },
  {"20111323 12:34:56", -1 },
  {"20110623 12:34:79", -1 },
  {"Wed, 31 Dec 2008 23:59:60 GMT", 1230768000 },
  {"Wed, 31 Dec 2008 23:59:61 GMT", -1 },
  {"Wed, 31 Dec 2008 24:00:00 GMT", -1 },
  {"Wed, 31 Dec 2008 23:60:59 GMT", -1 },
  {"20110623 12:3", 1308830580 },
  {"20110623 1:3", 1308790980 },
  {"20110623 1:30", 1308792600 },
  {"20110623 12:12:3", 1308831123 },
  {"20110623 01:12:3", 1308791523 },
  {"20110623 01:99:30", -1 },
  {"Thu, 01-Jan-1970 00:00:00 GMT", 0 },
  {"Thu, 31-Dec-1969 23:59:58 GMT", -2 },
  {"Thu, 31-Dec-1969 23:59:59 GMT", 0 }, /* avoids -1 ! */
#if SIZEOF_TIME_T > 4
  {"Sun, 06 Nov 2044 08:49:37 GMT", (time_t) CURL_OFF_TU_C(2362034977) },
  {"Sun, 06 Nov 3144 08:49:37 GMT", 37074617377 },
#ifndef HAVE_TIME_T_UNSIGNED
#if 0
  /* causes warning on MSVC */
  {"Sun, 06 Nov 1900 08:49:37 GMT", -2182259423 },
#endif
  {"Sun, 06 Nov 1800 08:49:37 GMT", -5337933023 },
  {"Thu, 01-Jan-1583 00:00:00 GMT", -12212553600 },
#endif
  {"Thu, 01-Jan-1499 00:00:00 GMT", -1 },
#else
  {"Sun, 06 Nov 2044 08:49:37 GMT", -1 },
#endif
#ifndef HAVE_TIME_T_UNSIGNED
  {"Sun, 06 Nov 1968 08:49:37 GMT", -36342623 },
#endif
  { NULL, 0 }
};

int test(char *URL)
{
  int i;
  int error = 0;

  (void)URL; /* not used */

  for(i = 0; dates[i].input; i++) {
    time_t out = curl_getdate(dates[i].input, NULL);
    if(out != dates[i].output) {
      printf("WRONGLY %s => %ld (instead of %ld)\n",
             dates[i].input, (long)out, (long)dates[i].output);
      error++;
    }
  }

  return error;
}
