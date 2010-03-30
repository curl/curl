/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 *
 */
#include "test.h"

/*
 * Simply download a HTTPS file!
 *
 * This test was added after the HTTPS-using-multi-interface with OpenSSL
 * regression of 7.19.1 to hopefully prevent this embarassing mistake from
 * appearing again... Unfortunately the bug wasn't triggered by this test,
 * which presumably is because the connect to a local server is too
 * fast/different compared to the real/distant servers we saw the bug happen
 * with.
 */
int test(char *URL)
{
  CURL *http_handle;
  CURLM *multi_handle = NULL;
  CURLMcode code;
  int res;

  int still_running; /* keep number of running handles */

  http_handle = curl_easy_init();
  if (!http_handle)
    return TEST_ERR_MAJOR_BAD;

  /* set options */
  test_setopt(http_handle, CURLOPT_URL, URL);
  test_setopt(http_handle, CURLOPT_HEADER, 1L);
  test_setopt(http_handle, CURLOPT_SSL_VERIFYPEER, 0L);
  test_setopt(http_handle, CURLOPT_SSL_VERIFYHOST, 0L);

  /* init a multi stack */
  multi_handle = curl_multi_init();
  if (!multi_handle) {
    curl_easy_cleanup(http_handle);
    return TEST_ERR_MAJOR_BAD;
  }

  /* add the individual transfers */
  curl_multi_add_handle(multi_handle, http_handle);

  /* we start some action by calling perform right away */
  do {
    code = curl_multi_perform(multi_handle, &still_running);
  } while(code == CURLM_CALL_MULTI_PERFORM);

  while(still_running) {
    struct timeval timeout;
    int rc; /* select() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    /* get file descriptors from the transfers */
    curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* In a real-world program you OF COURSE check the return code of the
       function calls, *and* you make sure that maxfd is bigger than -1 so
       that the call to select() below makes sense! */

    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0:
    default:
      /* timeout or readable/writable sockets */
      do {
        code = curl_multi_perform(multi_handle, &still_running);
      } while(code == CURLM_CALL_MULTI_PERFORM);
      break;
    }
  }

test_cleanup:

  if(multi_handle)
    curl_multi_cleanup(multi_handle);

  curl_easy_cleanup(http_handle);
  curl_global_cleanup();

  return res;
}
