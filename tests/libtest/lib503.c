#include "test.h"

#include <sys/time.h>
#include <sys/types.h>

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

  curl_global_init(CURL_GLOBAL_ALL);
  c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_PROXY, arg2); /* set in first.c */
  curl_easy_setopt(c, CURLOPT_URL, URL);
  curl_easy_setopt(c, CURLOPT_USERPWD, "test:ing");
  curl_easy_setopt(c, CURLOPT_PROXYUSERPWD, "test:ing");
  curl_easy_setopt(c, CURLOPT_HTTPPROXYTUNNEL, 1);
  curl_easy_setopt(c, CURLOPT_HEADER, 1);

  {
    CURLMcode res;
    int running;
    char done=FALSE;

    m = curl_multi_init();

    res = curl_multi_add_handle(m, c);

    while(!done) {
      fd_set rd, wr, exc;
      int max_fd;
      struct timeval interval;

      interval.tv_sec = 1;
      interval.tv_usec = 0;

      while (res == CURLM_CALL_MULTI_PERFORM) {
        res = curl_multi_perform(m, &running);
        if (running <= 0) {
          done = TRUE;
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
        return 89;
      }

      if (select(max_fd+1, &rd, &wr, &exc, &interval) == -1) {
        fprintf(stderr, "bad select??\n");
        return 95;
      }

      res = CURLM_CALL_MULTI_PERFORM;
    }
  }
  curl_multi_remove_handle(m, c);
  curl_easy_cleanup(c);
  curl_multi_cleanup(m);

  return CURLE_OK;
}

