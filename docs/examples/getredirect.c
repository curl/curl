/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * Show how to extract Location: header and URL to redirect to.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;
  char *location;
  long response_code;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* example.com is redirected, figure out the redirection! */

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    else {
      res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      if((res == CURLE_OK) &&
         ((response_code / 100) != 3)) {
        /* a redirect implies a 3xx response code */
        fprintf(stderr, "Not a redirect.\n");
      }
      else {
        res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &location);

        if((res == CURLE_OK) && location) {
          /* This is the new absolute URL that you could redirect to, even if
           * the Location: response header may have been a relative URL. */
          printf("Redirected to: %s\n", location);
        }
      }
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
