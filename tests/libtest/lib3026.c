/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#include <unistd.h>

#define NUM_THREADS 1000

static void *run_thread(void *ptr)
{
  CURLcode *result = ptr;

  *result = curl_global_init(CURL_GLOBAL_ALL);
  if(*result == CURLE_OK)
    curl_global_cleanup();

  return NULL;
}

int test(char *URL)
{
  CURLcode results[NUM_THREADS];
  pthread_t tids[NUM_THREADS];
  unsigned tid_count = NUM_THREADS, i;
  int test_failure = 0;
  curl_version_info_data *ver;
  (void) URL;

  ver = curl_version_info(CURLVERSION_NOW);
  if((ver->features & CURL_VERSION_THREADSAFE) == 0) {
    fprintf(stderr, "%s:%d Have pthread but the "
            "CURL_VERSION_THREADSAFE feature flag is not set\n",
            __FILE__, __LINE__);
    return -1;
  }

  for(i = 0; i < tid_count; i++) {
    int res = pthread_create(&tids[i], NULL, run_thread, &results[i]);
    if(res) {
      fprintf(stderr, "%s:%d Couldn't create thread, errno %d\n",
              __FILE__, __LINE__, res);
      tid_count = i;
      test_failure = -1;
      goto cleanup;
    }
  }

cleanup:
  for(i = 0; i < tid_count; i++) {
    pthread_join(tids[i], NULL);
    if(results[i] != CURLE_OK) {
      fprintf(stderr, "%s:%d thread[%u]: curl_global_init() failed,"
              "with code %d (%s)\n", __FILE__, __LINE__,
              i, (int) results[i], curl_easy_strerror(results[i]));
      test_failure = -1;
    }
  }

  return test_failure;
}

#else /* without pthread, this test doesn't work */
int test(char *URL)
{
  curl_version_info_data *ver;
  (void)URL;

  ver = curl_version_info(CURLVERSION_NOW);
  if((ver->features & CURL_VERSION_THREADSAFE) != 0) {
    fprintf(stderr, "%s:%d No pthread but the "
            "CURL_VERSION_THREADSAFE feature flag is set\n",
            __FILE__, __LINE__);
    return -1;
  }
  return 0;
}
#endif
