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

int test(char *URL)
{
  int res = 0;
  CURL *curl;
  int running;
  char done=FALSE;
  CURLM *m;
  int current=0;

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

  fprintf(stderr, "Start at URL 0\n");

  while(!done) {
    fd_set rd, wr, exc;
    int max_fd;
    struct timeval interval;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    while (res == CURLM_CALL_MULTI_PERFORM) {
      res = (int)curl_multi_perform(m, &running);
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
    if(done)
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

  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);

  curl_global_cleanup();
  return res;
}
