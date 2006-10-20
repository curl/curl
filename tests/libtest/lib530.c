/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     45 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 30 * 1000

#define NUM_HANDLES 4

int test(char *URL)
{
  int res = 0;
  CURL *curl[NUM_HANDLES];
  int running;
  char done=FALSE;
  CURLM *m;
  int i;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  m = curl_multi_init();

  /* get NUM_HANDLES easy handles */
  for(i=0; i < NUM_HANDLES; i++) {
    curl[i] = curl_easy_init();
    if(!curl[i]) {
      curl_global_cleanup();
      return 100 + i; /* major bad */
    }
    curl_easy_setopt(curl[i], CURLOPT_URL, URL);

    /* go verbose */
    curl_easy_setopt(curl[i], CURLOPT_VERBOSE, 1);

    /* include headers */
    curl_easy_setopt(curl[i], CURLOPT_HEADER, 1);

    res = (int)curl_multi_add_handle(m, curl[i]);
  }

  curl_multi_setopt(m, CURLMOPT_PIPELINING, 1);

  ml_timedout = FALSE;
  ml_start = curlx_tvnow();

  fprintf(stderr, "Start at URL 0\n");

  while (!done) {
    fd_set rd, wr, exc;
    int max_fd;
    struct timeval interval;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    if (curlx_tvdiff(curlx_tvnow(), ml_start) > 
        MAIN_LOOP_HANG_TIMEOUT) {
      ml_timedout = TRUE;
      break;
    }
    mp_timedout = FALSE;
    mp_start = curlx_tvnow();

    while (res == CURLM_CALL_MULTI_PERFORM) {
      res = (int)curl_multi_perform(m, &running);
      if (curlx_tvdiff(curlx_tvnow(), mp_start) > 
          MULTI_PERFORM_HANG_TIMEOUT) {
        mp_timedout = TRUE;
        break;
      }
      if (running <= 0) {
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
    res = 77;
  }

  /* get NUM_HANDLES easy handles */
  for(i=0; i < NUM_HANDLES; i++) {
    curl_multi_remove_handle(m, curl[i]);
    curl_easy_cleanup(curl[i]);
  }

  curl_multi_cleanup(m);

  curl_global_cleanup();
  return res;
}
