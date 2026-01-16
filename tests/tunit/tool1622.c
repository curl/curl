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

#include "tool_progress.h"

static CURLcode test_tool1622(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  {
    char buffer[9];
    curl_off_t secs;
    int i;
    static const curl_off_t check[] = {
      /* bytes to check */
      131072,
      12645826,
      1073741824,
      12938588979,
      1099445657078333,
      0 /* end of list */
    };

    puts("time2str");
    for(i = 0, secs = 0; i < 63; i++) {
      time2str(buffer, sizeof(buffer), secs);
      curl_mprintf("%20" FMT_OFF_T " - %s\n", secs, buffer);
      if(strlen(buffer) != 8) {
        curl_mprintf("^^ was too long!\n");
      }
      secs *= 2;
      secs++;
    }
    puts("max5data");
    for(i = 0, secs = 0; i < 63; i++) {
      max5data(secs, buffer, sizeof(buffer));
      curl_mprintf("%20" FMT_OFF_T " - %s\n", secs, buffer);
      if(strlen(buffer) != 5) {
        curl_mprintf("^^ was too long!\n");
      }
      secs *= 2;
      secs++;
    }
    for(i = 0; check[i]; i++) {
      secs = check[i];
      max5data(secs, buffer, sizeof(buffer));
      curl_mprintf("%20" FMT_OFF_T " - %s\n", secs, buffer);
      if(strlen(buffer) != 5) {
        curl_mprintf("^^ was too long!\n");
      }
    }
  }
  UNITTEST_END_SIMPLE
}
