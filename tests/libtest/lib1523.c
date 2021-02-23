/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "test.h"

/* test case and code based on https://github.com/curl/curl/issues/3927 */

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static int dload_progress_cb(void *a, curl_off_t b, curl_off_t c,
                             curl_off_t d, curl_off_t e)
{
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  return 0;
}

static size_t write_cb(char *d, size_t n, size_t l, void *p)
{
  /* take care of the data here, ignored in this example */
  (void)d;
  (void)p;
  return n*l;
}

static CURLcode run(CURL *hnd, long limit, long time)
{
  curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_LIMIT, limit);
  curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_TIME, time);
  return curl_easy_perform(hnd);
}

int test(char *URL)
{
  CURLcode ret;
  CURL *hnd;
  char buffer[CURL_ERROR_SIZE];
  curl_global_init(CURL_GLOBAL_ALL);
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, URL);
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(hnd, CURLOPT_ERRORBUFFER, buffer);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(hnd, CURLOPT_XFERINFOFUNCTION, dload_progress_cb);

  printf("Start: %d\n", time(NULL));
  ret = run(hnd, 1, 2);
  if(ret)
    fprintf(stderr, "error %d: %s\n", ret, buffer);

  ret = run(hnd, 12000, 1);
  if(ret != CURLE_OPERATION_TIMEDOUT)
    fprintf(stderr, "error %d: %s\n", ret, buffer);
  else
    ret = 0;

  printf("End: %d\n", time(NULL));
  curl_easy_cleanup(hnd);
  curl_global_cleanup();

  return (int)ret;
}
