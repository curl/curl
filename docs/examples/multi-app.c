/*
 * This is an example application source code using the multi interface.
 */

#include <stdio.h>
#include <string.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>


/* To start with, we include the header from the lib directory. This should
   later of course be moved to the proper include dir. */
#include "../lib/multi.h"

/*
 * Download a HTTP file and upload an FTP file simultaneously.
 */
int main(int argc, char **argv)
{
  CURL *http_handle;
  CURL *ftp_handle;
  CURLM *multi_handle;

  int still_running; /* keep number of running handles */

  http_handle = curl_easy_init();
  ftp_handle  = curl_easy_init();

  /* set the options (I left out a few, you'll get the point anyway) */
  curl_easy_setopt(http_handle, CURLOPT_URL, "http://website.com");

  curl_easy_setopt(ftp_handle, CURLOPT_URL, "ftp://ftpsite.com");
  curl_easy_setopt(ftp_handle, CURLOPT_UPLOAD, TRUE);

  /* init a multi stack */
  multi_handle = curl_multi_init();

  /* add the individual transfers */
  curl_multi_add_handle(multi_handle, http_handle);
  curl_multi_add_handle(multi_handle, ftp_handle);

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

    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0:
      /* timeout, do something else */
      break;
    default:
      /* one or more of curl's file descriptors say there's data to read
         or write */
      curl_multi_perform(multi_handle, &still_running);
      break;
    }
  }

  curl_multi_cleanup(multi_handle);

  curl_easy_cleanup(http_handle);
  curl_easy_cleanup(ftp_handle);


  return 0;
}
