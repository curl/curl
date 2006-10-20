#include "test.h"

#include <sys/time.h>
#include <sys/types.h>

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     30 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 20 * 1000

/*
 * Source code in here hugely as reported in bug report 651464 by
 * Christopher R. Palmer.
 *
 * Use multi interface to get document over proxy with bad port number.
 * This caused the interface to "hang" in libcurl 7.10.2.
 */
int test(char *URL)
{
  CURL *c;
  int ret=0;
  CURLM *m;
  fd_set rd, wr, exc;
  CURLMcode res;
  int running;
  int max_fd;
  int rc;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  curl_global_init(CURL_GLOBAL_ALL);
  c = curl_easy_init();

  /* the point here being that there must not run anything on the given
     proxy port */
  curl_easy_setopt(c, CURLOPT_PROXY, arg2);
  curl_easy_setopt(c, CURLOPT_URL, URL);
  curl_easy_setopt(c, CURLOPT_VERBOSE, 1);

  m = curl_multi_init();

  res = curl_multi_add_handle(m, c);
  if(res && (res != CURLM_CALL_MULTI_PERFORM))
    ; /* major failure */
  else {

    ml_timedout = FALSE;
    ml_start = curlx_tvnow();

    do {
      struct timeval interval;

      interval.tv_sec = 1;
      interval.tv_usec = 0;

      if (curlx_tvdiff(curlx_tvnow(), ml_start) > 
          MAIN_LOOP_HANG_TIMEOUT) {
        ml_timedout = TRUE;
        break;
      }

      fprintf(stderr, "curl_multi_perform()\n");

      mp_timedout = FALSE;
      mp_start = curlx_tvnow();

      do {
        res = curl_multi_perform(m, &running);
        if (curlx_tvdiff(curlx_tvnow(), mp_start) > 
            MULTI_PERFORM_HANG_TIMEOUT) {
          mp_timedout = TRUE;
          break;
        }
      } while (res == CURLM_CALL_MULTI_PERFORM);
      if (mp_timedout)
        break;
      if(!running) {
        /* This is where this code is expected to reach */
        int numleft;
        CURLMsg *msg = curl_multi_info_read(m, &numleft);
        fprintf(stderr, "Expected: not running\n");
        if(msg && !numleft)
          ret = 100; /* this is where we should be */
        else
          ret = 99; /* not correct */
        break;
      }
      fprintf(stderr, "running == %d, res == %d\n", running, res);

      if (res != CURLM_OK) {
        ret = 2;
        break;
      }

      FD_ZERO(&rd);
      FD_ZERO(&wr);
      FD_ZERO(&exc);
      max_fd = 0;

      fprintf(stderr, "curl_multi_fdset()\n");
      if (curl_multi_fdset(m, &rd, &wr, &exc, &max_fd) != CURLM_OK) {
        fprintf(stderr, "unexpected failured of fdset.\n");
        ret = 3;
        break;
      }
      rc = select_test(max_fd+1, &rd, &wr, &exc, &interval);
      fprintf(stderr, "select returned %d\n", rc);

    } while(1);
    if (ml_timedout || mp_timedout) {
      if (ml_timedout) fprintf(stderr, "ml_timedout\n");
      if (mp_timedout) fprintf(stderr, "mp_timedout\n");
      fprintf(stderr, "ABORTING TEST, since it seems "
              "that it would have run forever.\n");
      ret = 77;
    }
  }

  curl_multi_remove_handle(m, c);
  curl_easy_cleanup(c);
  curl_multi_cleanup(m);

  return ret;
}

