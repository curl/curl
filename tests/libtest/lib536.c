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

#define MAIN_LOOP_HANG_TIMEOUT     90 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

static CURLMcode perform(CURLM * multi)
{
  int handles, maxfd;
  CURLMcode code;
  fd_set fdread, fdwrite, fdexcep;
  struct timeval mp_start;
  char mp_timedout = FALSE;

  mp_timedout = FALSE;
  mp_start = tutil_tvnow();

  for (;;) {
    code = curl_multi_perform(multi, &handles);
    if (tutil_tvdiff(tutil_tvnow(), mp_start) >
        MULTI_PERFORM_HANG_TIMEOUT) {
      mp_timedout = TRUE;
      break;
    }
    if (handles <= 0)
      return CURLM_OK;

    switch (code) {
      case CURLM_OK:
        break;
      case CURLM_CALL_MULTI_PERFORM:
        continue;
      default:
        return code;
    }

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);
    curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
    if (maxfd < 0)
      return (CURLMcode) ~CURLM_OK;
    if (select(maxfd + 1, &fdread, &fdwrite, &fdexcep, 0) == -1)
      return (CURLMcode) ~CURLM_OK;
  }

  /* We only reach this point if (mp_timedout) */
  if (mp_timedout) fprintf(stderr, "mp_timedout\n");
  fprintf(stderr, "ABORTING TEST, since it seems "
          "that it would have run forever.\n");
  return (CURLMcode) ~CURLM_OK;
}

int test(char *URL)
{
  CURLM *multi;
  CURL *easy;
  int res = 0;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((multi = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if ((easy = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  curl_multi_setopt(multi, CURLMOPT_PIPELINING, 1L);

  test_setopt(easy, CURLOPT_WRITEFUNCTION, fwrite);
  test_setopt(easy, CURLOPT_FAILONERROR, 1L);
  test_setopt(easy, CURLOPT_URL, URL);

  if (curl_multi_add_handle(multi, easy) != CURLM_OK) {
    printf("curl_multi_add_handle() failed\n");
    res = TEST_ERR_MAJOR_BAD;
  } else {
    if (perform(multi) != CURLM_OK)
      printf("retrieve 1 failed\n");

    curl_multi_remove_handle(multi, easy);
  }
  curl_easy_reset(easy);

  test_setopt(easy, CURLOPT_FAILONERROR, 1L);
  test_setopt(easy, CURLOPT_URL, libtest_arg2);

  if (curl_multi_add_handle(multi, easy) != CURLM_OK) {
    printf("curl_multi_add_handle() 2 failed\n");
    res = TEST_ERR_MAJOR_BAD;
  } else {
    if (perform(multi) != CURLM_OK)
      printf("retrieve 2 failed\n");

    curl_multi_remove_handle(multi, easy);
  }

test_cleanup:

  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  printf("Finished!\n");

  return res;
}
