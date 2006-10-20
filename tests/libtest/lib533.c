/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

/* used for test case 533, 534 and 535 */

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     45 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 30 * 1000

int test(char *URL)
{
  int res = 0;
  CURL *curl;
  int running;
  char done=FALSE;
  CURLM *m;
  int current=0;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    return 100; /* major bad */
  }

  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

  m = curl_multi_init();

  res = (int)curl_multi_add_handle(m, curl);

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
        if(!current++) {
          fprintf(stderr, "Advancing to URL 1\n");
          /* remove the handle we use */
          curl_multi_remove_handle(m, curl);

          /* make us re-use the same handle all the time, and try resetting
             the handle first too */
          curl_easy_reset(curl);
          curl_easy_setopt(curl, CURLOPT_URL, arg2);
          curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
          curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

          /* re-add it */
          res = (int)curl_multi_add_handle(m, curl);
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
    res = 77;
  }

  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);

  curl_global_cleanup();
  return res;
}
