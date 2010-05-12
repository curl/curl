/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#include "memdebug.h"

static int new_fnmatch(const char *pattern, const char *string)
{
  (void)pattern;
  (void)string;
  return CURL_FNMATCHFUNC_MATCH;
}

int test(char *URL)
{
  int res;
  CURL *curl;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_WILDCARDMATCH, 1L);
  test_setopt(curl, CURLOPT_FNMATCH_FUNCTION, new_fnmatch);

  res = curl_easy_perform(curl);
  if(res) {
    fprintf(stderr, "curl_easy_perform() failed %d\n", res);
    goto test_cleanup;
  }
  res = curl_easy_perform(curl);
  if(res) {
    fprintf(stderr, "curl_easy_perform() failed %d\n", res);
    goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
