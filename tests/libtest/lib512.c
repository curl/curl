#include "test.h"

/* Test case code based on source in a bug report filed by James Bursa on
   28 Apr 2004 */

int test(char *URL)
{
  CURLcode code;
  CURL *curl;
  CURL *curl2;

  code = curl_global_init(CURL_GLOBAL_ALL);
  if(code != CURLE_OK)
    return 1;

  curl = curl_easy_init();
  if(!curl)
    return 2;

  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_HEADER, 1);

  curl2 = curl_easy_duphandle(curl);
  if(!curl2)
    return 3;

  code = curl_easy_setopt(curl2, CURLOPT_URL, URL);
  if(code != CURLE_OK)
    return 4;

  code = curl_easy_perform(curl2);
  if(code != CURLE_OK)
    return 5;

  curl_easy_cleanup(curl2);

  curl_easy_cleanup(curl);

  return 0;
}

