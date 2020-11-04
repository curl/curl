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
 * Set working URL with CURLU *.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

#if !CURL_AT_LEAST_VERSION(7, 62, 0)
#error "this example requires curl 7.62.0 or later"
#endif

int main(void)
{
  CURL *curl;
  CURLcode res;

  CURLU *urlp;
  CURLUcode uc;

  /* get a curl handle */
  curl = curl_easy_init();

  /* init Curl URL */
  urlp = curl_url();
  uc = curl_url_set(urlp, CURLUPART_URL,
                    "http://example.com/path/index.html", 0);

  if(uc) {
    fprintf(stderr, "curl_url_set() failed: %in", uc);
    goto cleanup;
  }

  if(curl) {
    /* set urlp to use as working URL */
    curl_easy_setopt(curl, CURLOPT_CURLU, urlp);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    goto cleanup;
  }

  cleanup:
  curl_url_cleanup(urlp);
  curl_easy_cleanup(curl);
  return 0;
}
