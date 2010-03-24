/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

/*
 * This code sets up multiple easy handles that transfer a single file from
 * the same URL, in a serial manner after each other. Due to the connection
 * sharing within the multi handle all transfers are performed on the same
 * persistent connection.
 *
 * This source code is used for lib526, lib527 and lib532 with only #ifdefs
 * controlling the small differences.
 *
 * - lib526 closes all easy handles after
 *   they all have transfered the file over the single connection
 * - lib527 closes each easy handle after each single transfer.
 * - lib532 uses only a single easy handle that is removed, reset and then
 *   re-added for each transfer
 *
 * Test case 526, 527 and 532 use FTP, while test 528 uses the lib526 tool but
 * with HTTP.
 */

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "testutil.h"
#include "memdebug.h"

#define MAIN_LOOP_HANG_TIMEOUT     90 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

#define NUM_HANDLES 4

int test(char *URL)
{
  int res = 0;
  CURL *curl[NUM_HANDLES];
  int running;
  char done=FALSE;
  CURLM *m = NULL;
  int current=0;
  int i, j;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* get NUM_HANDLES easy handles */
  for(i=0; i < NUM_HANDLES; i++) {
    curl[i] = curl_easy_init();
    if(!curl[i]) {
      fprintf(stderr, "curl_easy_init() failed "
              "on handle #%d\n", i);
      for (j=i-1; j >= 0; j--) {
        curl_easy_cleanup(curl[j]);
      }
      curl_global_cleanup();
      return TEST_ERR_MAJOR_BAD + i;
    }
    res = curl_easy_setopt(curl[i], CURLOPT_URL, URL);
    if(res) {
      fprintf(stderr, "curl_easy_setopt() failed "
              "on handle #%d\n", i);
      for (j=i; j >= 0; j--) {
        curl_easy_cleanup(curl[j]);
      }
      curl_global_cleanup();
      return TEST_ERR_MAJOR_BAD + i;
    }

    /* go verbose */
    res = curl_easy_setopt(curl[i], CURLOPT_VERBOSE, 1L);
    if(res) {
      fprintf(stderr, "curl_easy_setopt() failed "
              "on handle #%d\n", i);
      for (j=i; j >= 0; j--) {
        curl_easy_cleanup(curl[j]);
      }
      curl_global_cleanup();
      return TEST_ERR_MAJOR_BAD + i;
    }
  }

  if ((m = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    for(i=0; i < NUM_HANDLES; i++) {
      curl_easy_cleanup(curl[i]);
    }
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if ((res = (int)curl_multi_add_handle(m, curl[current])) != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle() failed, "
            "with code %d\n", res);
    curl_multi_cleanup(m);
    for(i=0; i < NUM_HANDLES; i++) {
      curl_easy_cleanup(curl[i]);
    }
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  ml_timedout = FALSE;
  ml_start = tutil_tvnow();

  fprintf(stderr, "Start at URL 0\n");

  while (!done) {
    fd_set rd, wr, exc;
    int max_fd;
    struct timeval interval;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    if (tutil_tvdiff(tutil_tvnow(), ml_start) >
        MAIN_LOOP_HANG_TIMEOUT) {
      ml_timedout = TRUE;
      break;
    }
    mp_timedout = FALSE;
    mp_start = tutil_tvnow();

    while (res == CURLM_CALL_MULTI_PERFORM) {
      res = (int)curl_multi_perform(m, &running);
      if (tutil_tvdiff(tutil_tvnow(), mp_start) >
          MULTI_PERFORM_HANG_TIMEOUT) {
        mp_timedout = TRUE;
        break;
      }
      if (running <= 0) {
#ifdef LIB527
        /* NOTE: this code does not remove the handle from the multi handle
           here, which would be the nice, sane and documented way of working.
           This however tests that the API survives this abuse gracefully. */
        curl_easy_cleanup(curl[current]);
#endif
        if(++current < NUM_HANDLES) {
          fprintf(stderr, "Advancing to URL %d\n", current);
#ifdef LIB532
          /* first remove the only handle we use */
          curl_multi_remove_handle(m, curl[0]);

          /* make us re-use the same handle all the time, and try resetting
             the handle first too */
          curl_easy_reset(curl[0]);
          test_setopt(curl[0], CURLOPT_URL, URL);
          test_setopt(curl[0], CURLOPT_VERBOSE, 1L);

          /* re-add it */
          res = (int)curl_multi_add_handle(m, curl[0]);
#else
          res = (int)curl_multi_add_handle(m, curl[current]);
#endif
          if(res) {
            fprintf(stderr, "add handle failed: %d.\n", res);
            res = 243;
            break;
          }
        }
        else
          done = TRUE; /* bail out */
        break;
      }
    }
    if (mp_timedout || done)
      break;

    if (res != CURLM_OK) {
      fprintf(stderr, "not okay???\n");
      break;
    }

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);
    max_fd = 0;

    if (curl_multi_fdset(m, &rd, &wr, &exc, &max_fd) != CURLM_OK) {
      fprintf(stderr, "unexpected failured of fdset.\n");
      res = 189;
      break;
    }

    if (select_test(max_fd+1, &rd, &wr, &exc, &interval) == -1) {
      fprintf(stderr, "bad select??\n");
      res = 195;
      break;
    }

    res = CURLM_CALL_MULTI_PERFORM;
  }

  if (ml_timedout || mp_timedout) {
    if (ml_timedout) fprintf(stderr, "ml_timedout\n");
    if (mp_timedout) fprintf(stderr, "mp_timedout\n");
    fprintf(stderr, "ABORTING TEST, since it seems "
            "that it would have run forever.\n");
    res = TEST_ERR_RUNS_FOREVER;
  }

#ifdef LIB532
test_cleanup:
#endif

#ifndef LIB527
  /* get NUM_HANDLES easy handles */
  for(i=0; i < NUM_HANDLES; i++) {
#ifdef LIB526
    if(m)
      curl_multi_remove_handle(m, curl[i]);
#endif
    curl_easy_cleanup(curl[i]);
  }
#endif
  if(m)
    curl_multi_cleanup(m);

  curl_global_cleanup();
  return res;
}
