/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013 - 2017, Linus Nielsen Feltzing, <linus@haxx.se>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

int test(char *URL)
{
  int res = 0;
  CURL *curl = NULL;

  fprintf(stderr, "test(%s)\n", URL);

  start_test_timing();

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Unset the OpenSSL default CA path */
  easy_setopt(curl, CURLOPT_CAPATH, NULL);
  /* Use our CA */
  easy_setopt(curl, CURLOPT_CAINFO, libtest_arg2);

  /* disconnect if we can't validate server's cert */
  easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

  /* Disable date check */
  easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_DATE_CHECK);

  res = curl_easy_perform(curl);
  if(res) {
    fprintf(stderr, "%s:%d curl_easy_perform() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }

test_cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
