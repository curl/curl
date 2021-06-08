/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

/* Testing Retry-After header parser */

#include "test.h"

#include "memdebug.h"

int test(char *URL)
{
  struct curl_slist *header = NULL;
  curl_off_t retry;
  CURL *curl = NULL;
  int res = 0;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  res = curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry);
  if(res)
    goto test_cleanup;

#ifdef LIB1596
  /* we get a relative number of seconds, so add the number of seconds
     we're at to make it a somewhat stable number. Then remove accuracy. */
  retry += time(NULL);
  retry /= 10000;
#endif
  printf("Retry-After %" CURL_FORMAT_CURL_OFF_T "\n", retry);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_slist_free_all(header);
  curl_global_cleanup();

  return res;
}
