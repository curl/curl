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
#include "first.h"

#include "memdebug.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>

#define CONN_NUM 3
#define TIME_BETWEEN_START_SECS 2

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static CURL *pending_handles[CONN_NUM];
static int pending_num = 0;
static CURLcode t1565_test_failure = CURLE_OK;

static CURLM *testmulti = NULL;
static const char *t1565_url;

static void *t1565_run_thread(void *ptr)
{
  CURL *easy = NULL;
  CURLcode res = CURLE_OK;
  int i;

  (void)ptr;

  for(i = 0; i < CONN_NUM; i++) {
    curlx_wait_ms(TIME_BETWEEN_START_SECS * 1000);

    easy_init(easy);

    easy_setopt(easy, CURLOPT_URL, t1565_url);
    easy_setopt(easy, CURLOPT_VERBOSE, 0L);

    pthread_mutex_lock(&lock);

    if(t1565_test_failure) {
      pthread_mutex_unlock(&lock);
      goto test_cleanup;
    }

    pending_handles[pending_num] = easy;
    pending_num++;
    easy = NULL;

    pthread_mutex_unlock(&lock);

    res_multi_wakeup(testmulti);
  }

test_cleanup:

  curl_easy_cleanup(easy);

  pthread_mutex_lock(&lock);

  if(!t1565_test_failure)
    t1565_test_failure = res;

  pthread_mutex_unlock(&lock);

  return NULL;
}

static CURLcode test_lib1565(char *URL)
{
  int still_running;
  int num;
  int i;
  int result;
  CURLcode res = CURLE_OK;
  CURL *started_handles[CONN_NUM];
  int started_num = 0;
  int finished_num = 0;
  pthread_t tid;
  bool tid_valid = false;
  struct CURLMsg *message;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(testmulti);

  t1565_url = URL;

  result = pthread_create(&tid, NULL, t1565_run_thread, NULL);
  if(!result)
    tid_valid = true;
  else {
    curl_mfprintf(stderr, "%s:%d Couldn't create thread, errno %d\n",
                  __FILE__, __LINE__, result);
    goto test_cleanup;
  }

  while(1) {
    multi_perform(testmulti, &still_running);

    abort_on_test_timeout();

    while((message = curl_multi_info_read(testmulti, &num))) {
      if(message->msg == CURLMSG_DONE) {
        res = message->data.result;
        if(res)
          goto test_cleanup;
        multi_remove_handle(testmulti, message->easy_handle);
        finished_num++;
      }
      else {
        curl_mfprintf(stderr,
                      "%s:%d Got an unexpected message from curl: %i\n",
                      __FILE__, __LINE__, (int)message->msg);
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }

      abort_on_test_timeout();
    }

    if(CONN_NUM == finished_num)
      break;

    multi_poll(testmulti, NULL, 0, TEST_HANG_TIMEOUT, &num);

    abort_on_test_timeout();

    pthread_mutex_lock(&lock);

    while(pending_num > 0) {
      res_multi_add_handle(testmulti, pending_handles[pending_num - 1]);
      if(res) {
        pthread_mutex_unlock(&lock);
        goto test_cleanup;
      }

      started_handles[started_num] = pending_handles[pending_num - 1];
      started_num++;
      pending_num--;
    }

    pthread_mutex_unlock(&lock);

    abort_on_test_timeout();
  }

  if(CONN_NUM != started_num) {
    curl_mfprintf(stderr, "%s:%d Not all connections started: %d of %d\n",
                  __FILE__, __LINE__, started_num, CONN_NUM);
    goto test_cleanup;
  }

  if(CONN_NUM != finished_num) {
    curl_mfprintf(stderr, "%s:%d Not all connections finished: %d of %d\n",
                  __FILE__, __LINE__, started_num, CONN_NUM);
    goto test_cleanup;
  }

test_cleanup:

  pthread_mutex_lock(&lock);
  if(!t1565_test_failure)
    t1565_test_failure = res;
  pthread_mutex_unlock(&lock);

  if(tid_valid)
    pthread_join(tid, NULL);

  curl_multi_cleanup(testmulti);
  for(i = 0; i < pending_num; i++)
    curl_easy_cleanup(pending_handles[i]);
  for(i = 0; i < started_num; i++)
    curl_easy_cleanup(started_handles[i]);
  curl_global_cleanup();

  return t1565_test_failure;
}

#else /* without pthread, this test doesn't work */
static CURLcode test_lib1565(char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif
