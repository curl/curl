/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#include "testutil.h"
#include "memdebug.h"

#define MAIN_LOOP_HANG_TIMEOUT     90 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

/*
 * Get a single URL without select().
 */

int test(char *URL)
{
  CURL *c;
  CURLM *m = NULL;
  int res = 0;
  int running=1;
  double connect_time = 0.0;
  struct timeval mp_start;
  char mp_timedout = FALSE;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((c = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(c, CURLOPT_HEADER, 1L);
  test_setopt(c, CURLOPT_URL, URL);

  if ((m = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    curl_easy_cleanup(c);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if ((res = (int)curl_multi_add_handle(m, c)) != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle() failed, "
            "with code %d\n", res);
    curl_multi_cleanup(m);
    curl_easy_cleanup(c);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  mp_timedout = FALSE;
  mp_start = tutil_tvnow();

  while (running) {
    res = (int)curl_multi_perform(m, &running);
    if (tutil_tvdiff(tutil_tvnow(), mp_start) >
        MULTI_PERFORM_HANG_TIMEOUT) {
      mp_timedout = TRUE;
      break;
    }
    if (running <= 0) {
      fprintf(stderr, "nothing left running.\n");
      break;
    }
  }

  if (mp_timedout) {
    if (mp_timedout) fprintf(stderr, "mp_timedout\n");
    fprintf(stderr, "ABORTING TEST, since it seems "
            "that it would have run forever.\n");
    res = TEST_ERR_RUNS_FOREVER;
  }

  curl_easy_getinfo(c, CURLINFO_CONNECT_TIME, &connect_time);
  if (connect_time <= 0.0) {
    fprintf(stderr, "connect time is <=0.0\n");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  if(m) {
    curl_multi_remove_handle(m, c);
    curl_multi_cleanup(m);
  }
  curl_easy_cleanup(c);
  curl_global_cleanup();

  return res;
}

