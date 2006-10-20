#include "test.h"

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     30 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 20 * 1000

int test(char *URL)
{
  CURL* curls;
  CURLM* multi;
  int still_running;
  int i = -1;
  CURLMsg *msg;
  CURLMcode res;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  multi = curl_multi_init();

  curls=curl_easy_init();
  curl_easy_setopt(curls, CURLOPT_URL, URL);
  curl_multi_add_handle(multi, curls);

  mp_timedout = FALSE;
  mp_start = curlx_tvnow();

  do {
    res = curl_multi_perform(multi, &still_running);
    if (curlx_tvdiff(curlx_tvnow(), mp_start) > 
        MULTI_PERFORM_HANG_TIMEOUT) {
      mp_timedout = TRUE;
      break;
    }
  } while (res == CURLM_CALL_MULTI_PERFORM);

  ml_timedout = FALSE;
  ml_start = curlx_tvnow();

  while ((!ml_timedout) && (!mp_timedout) && (still_running)) {
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

    if (curlx_tvdiff(curlx_tvnow(), ml_start) > 
        MAIN_LOOP_HANG_TIMEOUT) {
      ml_timedout = TRUE;
      break;
    }

    curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
    rc = select_test(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
    switch(rc) {
      case -1:
        break;
      case 0:
      default:
        mp_timedout = FALSE;
        mp_start = curlx_tvnow();
        do {
          res = curl_multi_perform(multi, &still_running);
          if (curlx_tvdiff(curlx_tvnow(), mp_start) > 
              MULTI_PERFORM_HANG_TIMEOUT) {
            mp_timedout = TRUE;
            break;
          }
        } while (res == CURLM_CALL_MULTI_PERFORM);
        break;
    }
  }
  if (ml_timedout || mp_timedout) {
    if (ml_timedout) fprintf(stderr, "ml_timedout\n");
    if (mp_timedout) fprintf(stderr, "mp_timedout\n");
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
