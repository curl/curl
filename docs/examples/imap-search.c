/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* <DESC>
 * Search for new IMAP emails
 * </DESC>
 */
#include <stdio.h>

#include <curl/curl.h>

/* This is a simple example showing how to search for new messages using
 * libcurl's IMAP capabilities.
 *
 * Note that this example requires libcurl 7.30.0 or above.
 */

int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    /* Set username and password */
    curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");

    /* This is mailbox folder to select */
    curl_easy_setopt(curl, CURLOPT_URL, "imap://imap.example.com/INBOX");

    /* Set the SEARCH command specifying what we want to search for. Note that
     * this can contain a message sequence set and a number of search criteria
     * keywords including flags such as ANSWERED, DELETED, DRAFT, FLAGGED, NEW,
     * RECENT and SEEN. For more information about the search criteria please
     * see RFC-3501 section 6.4.4.   */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "SEARCH NEW");

    /* Perform the custom request */
    result = curl_easy_perform(curl);

    /* Check for errors */
    if(result != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));

    /* Always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return (int)result;
}
