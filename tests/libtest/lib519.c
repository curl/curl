#include "test.h"

int test(char *URL)
{
  CURLcode res;
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

  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_USERPWD, "monster:underbed");
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, TRUE);

  /* get first page */
  res = curl_easy_perform(curl);

  curl_easy_setopt(curl, CURLOPT_USERPWD, "anothermonster:inwardrobe");

  /* get second page */
  res = curl_easy_perform(curl);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}

