#include "test.h"

#include <sys/time.h>
#include <sys/types.h>

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
    return 1; /* major failure */
  do {
    struct timeval interval;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    fprintf(stderr, "curl_multi_perform()\n");
    
    do {
      res = curl_multi_perform(m, &running);
    } while (res == CURLM_CALL_MULTI_PERFORM);
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
    rc = select(max_fd+1, &rd, &wr, &exc, &interval);
    fprintf(stderr, "select returned %d\n", rc);
    
  } while(rc);

  curl_multi_remove_handle(m, c);
  curl_easy_cleanup(c);
  curl_multi_cleanup(m);

  return ret;
}

