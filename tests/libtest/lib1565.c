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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#include <unistd.h>

#define TEST_HANG_TIMEOUT 60 * 1000
#define CONN_NUM 3
#define TIME_BETWEEN_START_SECS 2

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static CURL *pending_handles[CONN_NUM];
static int pending_num = 0;
static int test_failure = 0;

static CURLM *multi = NULL;
static const char *url;

static void *run_thread(void *ptr)
{
  CURL *easy = NULL;
  int res = 0;
  int i;

  (void)ptr;

  for(i = 0; i < CONN_NUM; i++) {
    wait_ms(TIME_BETWEEN_START_SECS * 1000);

    easy_init(easy);

    easy_setopt(easy, CURLOPT_URL, url);
    easy_setopt(easy, CURLOPT_VERBOSE, 0L);

    pthread_mutex_lock(&lock);

    if(test_failure) {
      pthread_mutex_unlock(&lock);
      goto test_cleanup;
    }

    pending_handles[pending_num] = easy;
    pending_num++;
    easy = NULL;

    pthread_mutex_unlock(&lock);

    res_multi_wakeup(multi);
  }

test_cleanup:

  curl_easy_cleanup(easy);

  pthread_mutex_lock(&lock);

  if(!test_failure)
    test_failure = res;

  pthread_mutex_unlock(&lock);

  return NULL;
}

int test(char *URL)
{
  int still_running;
  int num;
  int i;
  int res = 0;
  CURL *started_handles[CONN_NUM];
  int started_num = 0;
  int finished_num = 0;
  pthread_t tid;
  bool tid_valid = false;
  struct CURLMsg *message;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  url = URL;

  res = pthread_create(&tid, NULL, run_thread, NULL);
  if(!res)
    tid_valid = true;
  else {
    fprintf(stderr, "%s:%d Couldn't create thread, errno %d\n",
            __FILE__, __LINE__, res);
    goto test_cleanup;
  }

  while(1) {
    multi_perform(multi, &still_running);

    abort_on_test_timeout();

    while((message = curl_multi_info_read(multi, &num))) {
      if(message->msg == CURLMSG_DONE) {
        res = message->data.result;
        if(res)
          goto test_cleanup;
        multi_remove_handle(multi, message->easy_handle);
        finished_num++;
      }
      else {
        fprintf(stderr, "%s:%d Got an unexpected message from curl: %i\n",
              __FILE__, __LINE__, (int)message->msg);
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }

      abort_on_test_timeout();
    }

    if(CONN_NUM == finished_num)
      break;

    multi_poll(multi, NULL, 0, TEST_HANG_TIMEOUT, &num);

    abort_on_test_timeout();

    pthread_mutex_lock(&lock);

    while(pending_num > 0) {
      res_multi_add_handle(multi, pending_handles[pending_num - 1]);
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
    fprintf(stderr, "%s:%d Not all connections started: %d of %d\n",
            __FILE__, __LINE__, started_num, CONN_NUM);
    goto test_cleanup;
  }

  if(CONN_NUM != finished_num) {
    fprintf(stderr, "%s:%d Not all connections finished: %d of %d\n",
            __FILE__, __LINE__, started_num, CONN_NUM);
    goto test_cleanup;
  }

test_cleanup:

  pthread_mutex_lock(&lock);
  if(!test_failure)
    test_failure = res;
  pthread_mutex_unlock(&lock);

  if(tid_valid)
    pthread_join(tid, NULL);

  curl_multi_cleanup(multi);
  for(i = 0; i < pending_num; i++)
    curl_easy_cleanup(pending_handles[i]);
  for(i = 0; i < started_num; i++)
    curl_easy_cleanup(started_handles[i]);
  curl_global_cleanup();

  return test_failure;
}

#else /* without pthread, this test doesn't work */
int test(char *URL)
{
  (void)URL;
  return 0;
}
#endif
