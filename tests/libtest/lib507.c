/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#include "testutil.h"
#include "memdebug.h"

#define MAIN_LOOP_HANG_TIMEOUT     90 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

int test(char *URL)
{
  CURL* curls;
  CURLM* multi;
  int still_running;
  int i = -1;
  int res = 0;
  CURLMsg *msg;
  CURLMcode ret;
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((multi = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curls = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curls, CURLOPT_URL, URL);

  if ((ret = curl_multi_add_handle(multi, curls)) != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle() failed, "
            "with code %d\n", ret);
    curl_easy_cleanup(curls);
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  mp_timedout = FALSE;
  mp_start = tutil_tvnow();

  do {
    ret = curl_multi_perform(multi, &still_running);
    if (tutil_tvdiff(tutil_tvnow(), mp_start) >
        MULTI_PERFORM_HANG_TIMEOUT) {
      mp_timedout = TRUE;
      break;
    }
  } while (ret == CURLM_CALL_MULTI_PERFORM);

  ml_timedout = FALSE;
  ml_start = tutil_tvnow();

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

    if (tutil_tvdiff(tutil_tvnow(), ml_start) >
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
        mp_start = tutil_tvnow();
        do {
          ret = curl_multi_perform(multi, &still_running);
          if (tutil_tvdiff(tutil_tvnow(), mp_start) >
              MULTI_PERFORM_HANG_TIMEOUT) {
            mp_timedout = TRUE;
            break;
          }
        } while (ret == CURLM_CALL_MULTI_PERFORM);
        break;
    }
  }
  if (ml_timedout || mp_timedout) {
    if (ml_timedout) fprintf(stderr, "ml_timedout\n");
    if (mp_timedout) fprintf(stderr, "mp_timedout\n");
    fprintf(stderr, "ABORTING TEST, since it seems "
            "that it would have run forever.\n");
    i = TEST_ERR_RUNS_FOREVER;
  }
  else {
    msg = curl_multi_info_read(multi, &still_running);
    if(msg)
      /* this should now contain a result code from the easy handle,
         get it */
      i = msg->data.result;
  }

test_cleanup:

  curl_multi_cleanup(multi);
  curl_easy_cleanup(curls);
  curl_global_cleanup();

  if(res)
    i = res;

  return i; /* return the final return code */
}
