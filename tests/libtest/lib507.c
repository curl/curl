#include "test.h"

int test(char *URL)
{
  CURL* curls;
  CURLM* multi;
  int still_running;
  int i;
  CURLMsg *msg;

  multi = curl_multi_init();

  curls=curl_easy_init();
  curl_easy_setopt(curls, CURLOPT_URL, URL);
  curl_multi_add_handle(multi, curls);

  while ( CURLM_CALL_MULTI_PERFORM == curl_multi_perform(multi, &still_running) );
  while(still_running) {
    struct timeval timeout;
    int rc;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd;
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
    switch(rc) {
      case -1:
        break;
      case 0:
      default:
        while (CURLM_CALL_MULTI_PERFORM == curl_multi_perform(multi, &still_running));
        break;
    }
  }
  msg = curl_multi_info_read(multi, &still_running);
  /* this should now contain a result code from the easy handle,
     get it */
  i = msg->data.result;

  curl_multi_cleanup(multi);
  curl_easy_cleanup(curls);

  return i; /* return the final return code */
}
