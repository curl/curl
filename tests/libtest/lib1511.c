/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#include "testtrace.h"
#include "memdebug.h"

int test(char *URL)
{
  int i = -1;
  long unmet;
  CURLcode res = 0;
  CURL* curl = NULL;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HEADER, 1L);
  easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);

  /* TIMEVALUE in the future */
  easy_setopt(curl, CURLOPT_TIMEVALUE, 1566210680);

  res = curl_easy_perform(curl);
  if(res != CURLE_OK)
    goto test_cleanup;

  curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &unmet);
  if(unmet != 1)
    goto test_cleanup;

  /* TIMEVALUE in the past */
  easy_setopt(curl, CURLOPT_TIMEVALUE, 1);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    goto test_cleanup;

  curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &unmet);
  if(unmet != 0)
    goto test_cleanup;

  i = 0;

test_cleanup:
  if(res)
    i = res;

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return i; /* return the final return code */
}
