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

/* Test case code based on source in a bug report filed by James Bursa on
   28 Apr 2004 */

int test(char *URL)
{
  CURLcode code;
  CURL *curl;
  CURL *curl2;
  int rc = 99;

  code = curl_global_init(CURL_GLOBAL_ALL);
  if(code == CURLE_OK) {

    curl = curl_easy_init();
    if(curl) {

      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(curl, CURLOPT_HEADER, 1L);

      curl2 = curl_easy_duphandle(curl);
      if(curl2) {

        code = curl_easy_setopt(curl2, CURLOPT_URL, URL);
        if(code == CURLE_OK) {

          code = curl_easy_perform(curl2);
          if(code == CURLE_OK)
            rc = 0;
          else
            rc = 1;
        }
        else
          rc = 2;

        curl_easy_cleanup(curl2);
      }
      else
        rc = 3;

      curl_easy_cleanup(curl);
    }
    else
      rc = 4;

    curl_global_cleanup();
  }
  else
    rc = 5;

  return rc;
}

