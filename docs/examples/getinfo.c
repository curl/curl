/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;

  /* http://curl.haxx.se/libcurl/c/curl_easy_init.html */
  curl = curl_easy_init();
  if(curl) {
    /* http://curl.haxx.se/libcurl/c/curl_easy_setopt.html#CURLOPTURL */
    curl_easy_setopt(curl, CURLOPT_URL, "curl.haxx.se");
    /* http://curl.haxx.se/libcurl/c/curl_easy_perform.html */
    res = curl_easy_perform(curl);

    if(CURLE_OK == res) {
      char *ct;
      /* ask for the content-type */
      /* http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html */
      res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

      if((CURLE_OK == res) && ct)
        printf("We received Content-Type: %s\n", ct);
    }

    /* always cleanup */
    /* http://curl.haxx.se/libcurl/c/curl_easy_cleanup.html */
    curl_easy_cleanup(curl);
  }
  return 0;
}
