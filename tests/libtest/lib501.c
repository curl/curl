#include "test.h"

int test(char *URL)
{
  CURLcode res;
  CURL *curl = curl_easy_init();

  (void)URL; /* we don't use this */
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  return res;
}

