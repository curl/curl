#include "test.h"

int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;

  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. */
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, NULL);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1); /* show verbose for debug */
    curl_easy_setopt(curl, CURLOPT_HEADER, 1); /* include header */

    /* Now, we should be making a zero byte POST request */
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return (int)res;
}
