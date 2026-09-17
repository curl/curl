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
#include "unitcheck.h"

static CURLcode test_unit4781(const char *arg)
{
#ifndef CURL_DISABLE_PARSEDATE
  unsigned int i;
  int errors = 0;
  struct day {
    const char *name;
    int val;
  };

  /* three-letter version or full version, nothing else */
  static const struct day days[] = {
    { "wedmesday", -1 },
    { "monray", -1 },
    { "mon", 0 },
    { "tue", 1 },
    { "wed", 2 },
    { "thu", 3 },
    { "fri", 4 },
    { "sat", 5 },
    { "sun", 6 },
    { "monday", 0 },
    { "tuesday", 1 },
    { "wednesday", 2 },
    { "thursday", 3 },
    { "friday", 4 },
    { "saturday", 5 },
    { "sunday", 6 },
    { "monDAY", 0 },
    { "tueSDAY", 1 },
    { "wedneSDAY", 2 },
    { "thursdAY", 3 },
    { "frIDAY", 4 },
    { "satURDAY", 5 },
    { "suNDAY", 6 },
    { "monda", -1 },
    { "tuesda", -1 },
    { "wednesda", -1 },
    { "thursda", -1 },
    { "frida", -1 },
    { "saturda", -1 },
    { "sunda", -1 },
    { "MON", 0 },
    { "TUE", 1 },
    { "WED", 2 },
    { "THU", 3 },
    { "FRI", 4 },
    { "SAT", 5 },
    { "SUN", 6 },
    { "mo", -1 },
    { "tu", -1 },
    { "we", -1 },
    { "th", -1 },
    { "fr", -1 },
    { "sa", -1 },
    { "su", -1 },
    { "mom", -1 },
    { "tuf", -1 },
    { "wef", -1 },
    { "thv", -1 },
    { "frj", -1 },
    { "sau", -1 },
    { "sum", -1 },
    { "abc", -1 },
    { " monday", -1 },
    { " tuesday", -1 },
    { " wednesday", -1 },
    { " thursday", -1 },
    { " friday", -1 },
    { " saturday", -1 },
    { " sunday", -1 },
    { "monday ", -1 },
    { "tuesday ", -1 },
    { "wednesday ", -1 },
    { "thursday ", -1 },
    { "friday ", -1 },
    { "saturday ", -1 },
    { "sunday ", -1 },
  };

  /* three-letter month versions only */
  static const struct day months[] = {
    { "monday", -1 },
    { "tuesday", -1 },
    { "wednesday", -1 },
    { "thursday", -1 },
    { "friday", -1 },
    { "saturday", -1 },
    { "jan", 0 },
    { "feb", 1 },
    { "mar", 2 },
    { "apr", 3 },
    { "may", 4 },
    { "jun", 5 },
    { "jul", 6 },
    { "aug", 7 },
    { "sep", 8 },
    { "oct", 9 },
    { "nov", 10 },
    { "dec", 11 },
    { "january", -1 },
    { "february", -1 },
    { "march", -1 },
    { "april", -1 },
    { "june", -1 },
    { "july", -1 },
    { "august", -1 },
    { "september", -1 },
    { "october", -1 },
    { "november", -1 },
    { "december", -1 },
    { "janu", -1 },
    { "febr", -1 },
    { "marc", -1 },
    { "apri", -1 },
    { "june", -1 },
    { "july", -1 },
    { "augu", -1 },
    { "sept", -1 },
    { "octo", -1 },
    { "nove", -1 },
    { "dece", -1 },
    { "JAN", 0 },
    { "FEB", 1 },
    { "MAR", 2 },
    { "APR", 3 },
    { "MAY", 4 },
    { "JUN", 5 },
    { "JUL", 6 },
    { "AUG", 7 },
    { "SEP", 8 },
    { "OCT", 9 },
    { "NOV", 10 },
    { "DEC", 11 },
  };

  static const struct day timezones[] = {
    { "A", -3600 },
    { "B", -7200 },
    { "a", -1 },
    { "b", -1 },
    { "C", -10800 },
    { "D", -14400 },
    { "E", -18000 },
    { "F", -21600 },
    { "G", -25200 },
    { "H", -28800 },
    { "I", -32400 },
    { "J", -1 },
    { "K", -36000 },
    { "L", -39600 },
    { "M", -43200 },
    { "N", 3600 },
    { "O", 7200 },
    { "P", 10800 },
    { "Q", 14400 },
    { "R", 18000 },
    { "S", 21600 },
    { "T", 25200 },
    { "U", 28800 },
    { "V", 32400 },
    { "X", 39600 },
    { "Y", 43200 },
    { "Z", 0 },
    { "z", -1 },
    { "@", -1 },

    { "NT", 39600 },
    { "UT", 0 },
    { "nt", -1 },
    { "ut", -1 },
    { "PT", -1 },
    { "CT", -1 },

    { "ADT", 10800 },
    { "AST", 14400 },
    { "BST", -3600 },
    { "CAT", 36000 },
    { "CCT", -28800 },
    { "CDT", 18000 },
    { "CET", -3600 },
    { "CST", 21600 },
    { "EDT", 14400 },
    { "EET", -7200 },
    { "EST", 18000 },
    { "FST", -7200 },
    { "FWT", -3600 },
    { "GMT", 0 },
    { "GST", -36000 },
    { "HDT", 32400 },
    { "HST", 36000 },
    { "JST", -32400 },
    { "MDT", 21600 },
    { "MET", -3600 },
    { "MST", 25200 },
    { "NZT", -43200 },
    { "PDT", 25200 },
    { "PST", 28800 },
    { "UTC", 0 },
    { "WAT", 3600 },
    { "WET", 0 },
    { "YDT", 28800 },
    { "YST", 32400 },
    { "yST", -1 },
    { "ZST", -1 },

    { "AHST", 36000 },
    { "BHST", -1 },
    { "ahst", -1 },
    { "CEST", -7200 },
    { "cest", -1 },
    { "EADT", -39600 },
    { "EAST", -36000 },
    { "IDLE", -43200 },
    { "IDLW", 43200 },
    { "MEST", -7200 },
    { "MESZ", -7200 },
    { "MEWT", -3600 },
    { "NZDT", -46800 },
    { "NZST", -43200 },
    { "WADT", -28800 },
    { "WAST", -25200 }  /* spellchecker:disable-line */
  };

    (void)arg;

  for(i = 0; i < CURL_ARRAYSIZE(days); i++) {
    int d = checkday(days[i].name, strlen(days[i].name));
    if(d != days[i].val) {
      curl_mfprintf(stderr, "Day: %s returned %d, expected %d\n",
                    days[i].name, d, days[i].val);
      errors++;
    }
  }
  for(i = 0; i < CURL_ARRAYSIZE(months); i++) {
    int d = checkmonth(months[i].name, strlen(months[i].name));
    if(d != months[i].val) {
      curl_mfprintf(stderr, "Month: %s returned %d, expected %d\n",
                    months[i].name, d, months[i].val);
      errors++;
    }
  }
  for(i = 0; i < CURL_ARRAYSIZE(timezones); i++) {
    int d = checktz(timezones[i].name, strlen(timezones[i].name));
    if(d != timezones[i].val) {
      curl_mfprintf(stderr, "TZ: %s returned %d, expected %d\n",
                    timezones[i].name, d, timezones[i].val);
      errors++;
    }
  }
  if(errors)
    return CURLE_BAD_FUNCTION_ARGUMENT;
#else /* CURL_DISABLE_PARSEDATE */
  /* nothing to do */
  (void)arg;
#endif
  return CURLE_OK;
}
