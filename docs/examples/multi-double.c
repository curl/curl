/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 *
 * This is a very simple example using the multi interface.
 */

#include <stdio.h>
#include <string.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>

/* curl stuff */
#include <curl/curl.h>

/*
 * Simply download two HTTP files!
 */
int main(int argc, char **argv)
{
  CURL *http_handle;
  CURL *http_handle2;
  CURLM *multi_handle;

  int still_running; /* keep number of running handles */

  http_handle = curl_easy_init();
  http_handle2 = curl_easy_init();

  /* set options */
  curl_easy_setopt(http_handle, CURLOPT_URL, "http://www.haxx.se/");

  /* set options */
  curl_easy_setopt(http_handle2, CURLOPT_URL, "http://localhost/");

  /* init a multi stack */
  multi_handle = curl_multi_init();

  /* add the individual transfers */
  curl_multi_add_handle(multi_handle, http_handle);
  curl_multi_add_handle(multi_handle, http_handle2);

  /* we start some action by calling perform right away */
  while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(multi_handle, &still_running));

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
      while(CURLM_CALL_MULTI_PERFORM ==
            curl_multi_perform(multi_handle, &still_running));
      break;
    }
  }

  curl_multi_cleanup(multi_handle);

  curl_easy_cleanup(http_handle);
  curl_easy_cleanup(http_handle2);

  return 0;
}
