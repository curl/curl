#include "test.h"

int test(char *URL)
{
  CURLcode res;
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_FILETIME, 1);
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  return (int)res;
}
