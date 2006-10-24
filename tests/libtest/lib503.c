#include "test.h"

#include <sys/time.h>
#include <sys/types.h>

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     300 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 120 * 1000

/*
 * Source code in here hugely as reported in bug report 651460 by
 * Christopher R. Palmer.
 *
 * Use multi interface to get HTTPS document over proxy, and provide
 * auth info.
 */

int test(char *URL)
{
  CURL *c;
  CURLM *m;
  int res = 0;
  int running;
  char done = FALSE;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  curl_global_init(CURL_GLOBAL_ALL);
  c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_PROXY, arg2); /* set in first.c */
  curl_easy_setopt(c, CURLOPT_URL, URL);
  curl_easy_setopt(c, CURLOPT_USERPWD, "test:ing");
  curl_easy_setopt(c, CURLOPT_PROXYUSERPWD, "test:ing");
  curl_easy_setopt(c, CURLOPT_HTTPPROXYTUNNEL, 1);
  curl_easy_setopt(c, CURLOPT_HEADER, 1);


  m = curl_multi_init();

  res = (int)curl_multi_add_handle(m, c);

  ml_timedout = FALSE;
  ml_start = curlx_tvnow();

  while(!done) {
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
        done = TRUE;
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
      res = 89;
      break;
    }

    if (select_test(max_fd+1, &rd, &wr, &exc, &interval) == -1) {
      fprintf(stderr, "bad select??\n");
      res = 95;
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

  curl_multi_remove_handle(m, c);
  curl_easy_cleanup(c);
  curl_multi_cleanup(m);

  curl_global_cleanup();
  return res;
}

