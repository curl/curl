/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "testutil.h"
#include "memdebug.h"

/* 3x download!
 * 1. normal
 * 2. dup handle
 * 3. with multi interface
 */

int test(char *URL)
{
  CURLMcode m;
  CURL *handle = NULL, *duphandle;
  CURLM *mhandle = NULL;
  int res = 0;
  int still_running = 0;

  if(curl_global_init(CURL_GLOBAL_ALL)) {
    fprintf(stderr, "curl_global_init() failed\n");
    goto test_cleanup;
  }

  handle = curl_easy_init();
  if(!handle) {
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  test_setopt(handle, CURLOPT_URL, URL);
  test_setopt(handle, CURLOPT_WILDCARDMATCH, 1L);
  test_setopt(handle, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(handle);
  if(res)
    goto test_cleanup;

  res = curl_easy_perform(handle);
  if(res)
    goto test_cleanup;

  duphandle = curl_easy_duphandle(handle);
  if(!duphandle)
    goto test_cleanup;
  curl_easy_cleanup(handle);
  handle = duphandle;

  mhandle = curl_multi_init();
  if(!mhandle) {
    fprintf(stderr, "curl_multi_init() failed\n");
    goto test_cleanup;
  }

  curl_multi_add_handle(mhandle, handle);

  while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(mhandle, &still_running));

  while(still_running) {
    static struct timeval timeout = /* 100 ms */ { 0, 100000L };
    int rc;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int max_fdset = -1;
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    m = curl_multi_fdset(mhandle, &fdread, &fdwrite, &fdexcep, &max_fdset);
    if(m != CURLM_OK) {
      fprintf(stderr, "curl_multi_fdset() error\n");
      goto test_cleanup;
    }
    /* We call select(max_fdset + 1, ...), specially in case of (maxfd == -1),
     * we call select(0, ...), which is basically equal to sleep. */
    rc = select(max_fdset + 1, &fdread, &fdwrite, &fdexcep, &timeout);
    if(rc == -1) {
      fprintf(stderr, "select() error\n");
      goto test_cleanup;
    }
    else {
      while(CURLM_CALL_MULTI_PERFORM ==
          curl_multi_perform(mhandle, &still_running));
    }
  }

test_cleanup:
  if(mhandle)
    curl_multi_cleanup(mhandle);
  if(handle)
    curl_easy_cleanup(handle);
  curl_global_cleanup();
  return res;
}
