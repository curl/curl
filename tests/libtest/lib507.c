#include "test.h"

int test(char *URL)
{
  CURL* curls;
  CURLM* multi;
  int still_running;
  int i = -1;
  CURLMsg *msg;
  int loop1 = 20;
  int loop2 = 40;

  multi = curl_multi_init();

  curls=curl_easy_init();
  curl_easy_setopt(curls, CURLOPT_URL, URL);
  curl_multi_add_handle(multi, curls);

  while ((--loop1>0) && (CURLM_CALL_MULTI_PERFORM == 
         curl_multi_perform(multi, &still_running)));

  while ((loop1>0) && (--loop2>0) && (still_running)) {
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
    rc = select_test(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
    switch(rc) {
      case -1:
        break;
      case 0:
      default:
        loop1 = 20;
        while ((--loop1>0) && (CURLM_CALL_MULTI_PERFORM == 
               curl_multi_perform(multi, &still_running)));
        break;
    }
  }
  if ((loop1 <= 0) || (loop2 <= 0)) {
    fprintf(stderr, "loop1: %d loop2: %d \n", loop1, loop2);
    fprintf(stderr, "ABORTING TEST, since it seems "
            "that it would have run forever.\n");
    i = 77;
  }
  else {
    msg = curl_multi_info_read(multi, &still_running);
    if(msg)
      /* this should now contain a result code from the easy handle,
         get it */
      i = msg->data.result;
  }

  curl_multi_cleanup(multi);
  curl_easy_cleanup(curls);

  return i; /* return the final return code */
}
