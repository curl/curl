/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
 * POP3 example showing how to delete e-mails
 * </DESC>
 */

#include <stdio.h>
#include <curl/curl.h>

/* This is a simple example showing how to delete an existing mail using
 * libcurl's POP3 capabilities.
 *
 * Note that this example requires libcurl 7.26.0 or above.
 */

int main(void)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  curl = curl_easy_init();
  if(curl) {
    /* Set username and password */
    curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");

    /* You can specify the message either in the URL or DELE command */
    curl_easy_setopt(curl, CURLOPT_URL, "pop3://pop.example.com/1");

    /* Set the DELE command */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELE");

    /* Do not perform a transfer as DELE returns no data */
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    /* Perform the custom request */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* Always cleanup */
    curl_easy_cleanup(curl);
  }

  return (int)res;
}
