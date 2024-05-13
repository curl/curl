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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

CURLcode test(char *URL)
{
  const struct curl_easyoption *o;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);

  for(o = curl_easy_option_next(NULL);
      o;
      o = curl_easy_option_next(o)) {
    const struct curl_easyoption *ename =
      curl_easy_option_by_name(o->name);
    const struct curl_easyoption *eid =
      curl_easy_option_by_id(o->id);

    if(ename->id != o->id) {
      printf("name lookup id %d doesn't match %d\n",
             ename->id, o->id);
    }
    else if(eid->id != o->id) {
      printf("ID lookup %d doesn't match %d\n",
             ename->id, o->id);
    }
  }
  curl_global_cleanup();
  return CURLE_OK;
}
