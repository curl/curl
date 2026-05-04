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

#include "parsedate.h"
#include "curl_setup.h"

static CURLcode test_unit3302(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct dcheck {
    const char *input;
    time_t output;
    bool fail;
  };

  static const struct dcheck dates[] = {
    /* normal valid date - should still parse correctly */
    { "Sun, 06 Nov 1994 08:49:37 GMT", 784111777, FALSE },
    /* malformed - should still fail */
    { "MalformedTimestamp", 0, TRUE },
#if SIZEOF_TIME_T < 5
    /* just before 32-bit overflow - should parse without capping */
    { "Tue, 19 Jan 2038 03:14:07 GMT", 2147483647, FALSE },
    /* just after 32-bit overflow - should be capped to TIME_T_MAX, 2147483648*/
    { "Tue, 19 Jan 2038 03:14:08 GMT", TIME_T_MAX, FALSE },
    /* far future date overflows time_t - capped to TIME_T_MAX, 37074617377 */
    { "Sun, 06 Nov 3144 08:49:37 GMT", TIME_T_MAX, FALSE },
#else
    /* on 64-bit, far future date should parse to its real value, not capped */
    { "Sun, 06 Nov 3144 08:49:37 GMT", 37074617377, FALSE },
#endif
    { NULL, 0, FALSE }
  };

  int i;
  int error = 0;

  (void)arg;

  for(i = 0; dates[i].input; i++) {
    time_t t = 0;
    int rc = Curl_getdate_capped(dates[i].input, &t);
    if(dates[i].fail) {
      if(!rc) {
        curl_mprintf("WRONGLY parsed '%s' => %" CURL_FORMAT_CURL_OFF_T "\n",
                     dates[i].input, (curl_off_t)t);
        error++;
      }
    }
    else {
      if(rc || t != dates[i].output) {
        curl_mprintf("WRONGLY %s => %" CURL_FORMAT_CURL_OFF_T
                     " (instead of %" CURL_FORMAT_CURL_OFF_T ")\n",
                     dates[i].input,
                     (curl_off_t)t, (curl_off_t)dates[i].output);
        error++;
      }
    }
  }

  fail_unless(error == 0, "date parsing failures");

  UNITTEST_END_SIMPLE
}
