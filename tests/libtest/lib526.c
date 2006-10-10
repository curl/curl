/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
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

#define NUM_HANDLES 4

int test(char *URL)
{
  int res = 0;
  CURL *curl[NUM_HANDLES];
  int running;
  char done=FALSE;
  CURLM *m;
  int current=0;
  int i;

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

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
  }

  m = curl_multi_init();

  res = (int)curl_multi_add_handle(m, curl[current]);

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
          curl_easy_setopt(curl[0], CURLOPT_URL, URL);
          curl_easy_setopt(curl[0], CURLOPT_VERBOSE, 1);

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

#ifndef LIB527
  /* get NUM_HANDLES easy handles */
  for(i=0; i < NUM_HANDLES; i++) {
#ifdef LIB526
    curl_multi_remove_handle(m, curl[i]);
#endif
    curl_easy_cleanup(curl[i]);
  }
#endif
  curl_multi_cleanup(m);

  curl_global_cleanup();
  return res;
}
