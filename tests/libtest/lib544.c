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

static char teststring[] =
#ifdef CURL_DOES_CONVERSIONS
  /* ASCII representation with escape sequences for non-ASCII platforms */
  "\x54\x68\x69\x73\x00\x20\x69\x73\x20\x74\x65\x73\x74\x20\x62\x69\x6e\x61"
  "\x72\x79\x20\x64\x61\x74\x61\x20\x77\x69\x74\x68\x20\x61\x6e\x20\x65\x6d"
  "\x62\x65\x64\x64\x65\x64\x20\x4e\x55\x4c\x20\x62\x79\x74\x65\x0a";
#else
  "This\0 is test binary data with an embedded NUL byte\n";
#endif


int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

#ifdef LIB545
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) sizeof teststring - 1);
#endif

  test_setopt(curl, CURLOPT_COPYPOSTFIELDS, teststring);

  test_setopt(curl, CURLOPT_VERBOSE, 1L); /* show verbose for debug */
  test_setopt(curl, CURLOPT_HEADER, 1L); /* include header */

  /* Update the original data to detect non-copy. */
  strcpy(teststring, "FAIL");

  /* Now, this is a POST request with binary 0 embedded in POST data. */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
