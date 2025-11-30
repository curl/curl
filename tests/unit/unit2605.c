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
#include "vssh/vssh.h"

static CURLcode test_unit2605(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_SSH
  CURL *curl;
  struct range {
    const char *r;
    curl_off_t filesize;
    curl_off_t start;
    curl_off_t size;
    CURLcode res;
  };

  int i;
  struct range list[] = {
    { "0-9", 100, 0, 10, CURLE_OK },
    { "1-10", 100, 1, 10, CURLE_OK },
    { "222222-222222", 300000, 222222, 1, CURLE_OK },
    { "4294967296 - 4294967297", 4294967298, 4294967296, 2, CURLE_OK },
    { "-10", 100, 90, 10, CURLE_OK },
    { "-20", 100, 80, 20, CURLE_OK },
    { "-1", 100, 99, 1, CURLE_OK },
    { "-0", 100, 0, 0, CURLE_RANGE_ERROR },
    { "--2", 100, 0, 0, CURLE_RANGE_ERROR },
    { "-100", 100, 0, 100, CURLE_OK },
    { "-101", 100, 0, 100, CURLE_OK },
    { "-1000", 100, 0, 100, CURLE_OK },
    { "2-1000", 100, 2, 98, CURLE_OK },
    { ".2-3", 100, 0, 0, CURLE_RANGE_ERROR },
    { "+2-3", 100, 0, 0, CURLE_RANGE_ERROR },
    { "2 - 3", 100, 2, 2, CURLE_OK },
    { " 2 - 3", 100, 2, 2, CURLE_RANGE_ERROR }, /* no leading space */
    { "2 - 3 ", 100, 2, 2, CURLE_RANGE_ERROR }, /* no trailing space */
    { "3-2", 100, 0, 0, CURLE_RANGE_ERROR },
    { "2.-3", 100, 0, 0, CURLE_RANGE_ERROR },
    { "-3-2", 100, 0, 0, CURLE_RANGE_ERROR },
    { "101-102", 100, 0, 0, CURLE_RANGE_ERROR },
    { "0-", 100, 0, 100, CURLE_OK },
    { "1-", 100, 1, 99, CURLE_OK },
    { "99-", 100, 99, 1, CURLE_OK },
    { "100-", 100, 0, 0, CURLE_RANGE_ERROR },
    { NULL, 0, 0, 0, CURLE_OK }
  };

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    for(i = 0; list[i].r; i++) {
      curl_off_t start;
      curl_off_t size;
      CURLcode res;
      curl_mprintf("%u: '%s' (file size: %" FMT_OFF_T ")\n", i, list[i].r,
                   list[i].filesize);
      res = Curl_ssh_range(curl, list[i].r, list[i].filesize, &start, &size);
      if(res != list[i].res) {
        curl_mprintf("... returned %d\n", res);
        unitfail++;
      }
      if(!res) {
        if(start != list[i].start) {
          curl_mprintf("... start (%" FMT_OFF_T ") was not %" FMT_OFF_T " \n",
                       start, list[i].start);
          unitfail++;
        }
        if(size != list[i].size) {
          curl_mprintf("... size (%" FMT_OFF_T ") was not %" FMT_OFF_T " \n",
                       size, list[i].size);
          unitfail++;
        }
      }
    }
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  if(!unitfail)
    curl_mprintf("ok\n");

#endif

  UNITTEST_END_SIMPLE
}
