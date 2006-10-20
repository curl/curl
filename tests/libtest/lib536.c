/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     45 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 30 * 1000

static CURLMcode perform(CURLM * multi);

static CURLMcode perform(CURLM * multi)
{
  int handles, maxfd;
  CURLMcode code;
  fd_set fdread, fdwrite, fdexcep;
  struct timeval mp_start;
  char mp_timedout = FALSE;

  mp_timedout = FALSE;
  mp_start = curlx_tvnow();

  for (;;) {
    code = curl_multi_perform(multi, &handles);
    if (curlx_tvdiff(curlx_tvnow(), mp_start) > 
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
  fprintf(stderr, "mp_timedout\n");
  fprintf(stderr, "ABORTING TEST, since it seems "
          "that it would have run forever.\n");
  return (CURLMcode) ~CURLM_OK;
}

int test(char *URL)
{
  CURLM *multi = curl_multi_init();
  CURL *easy = curl_easy_init();

  curl_multi_setopt(multi, CURLMOPT_PIPELINING, 1);

  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, fwrite);
  curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt(easy, CURLOPT_URL, URL);

  curl_multi_add_handle(multi, easy);
  if (perform(multi) != CURLM_OK)
    printf("retrieve 1 failed\n");

  curl_multi_remove_handle(multi, easy);
  curl_easy_reset(easy);

  curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt(easy, CURLOPT_URL, arg2);

  curl_multi_add_handle(multi, easy);
  if (perform(multi) != CURLM_OK)
    printf("retrieve 2 failed\n");

  curl_multi_remove_handle(multi, easy);
  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);

  printf("Finished!\n");

  return 0;
}
