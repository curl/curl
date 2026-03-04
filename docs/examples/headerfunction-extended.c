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
 * Demonstrate the CURLOPT_HEADERFUNCTION_EXTENDED callback which provides
 * information about header origin/type (regular, trailer, 1xx, etc.)
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>
#include <curl/header.h>

static size_t header_callback_ex(char *buffer, size_t size,
                                  size_t nitems, unsigned int origin,
                                  void *userdata)
{
  size_t bytes = size * nitems;
  (void)userdata; /* not used in this example */

  /* Print header type prefix based on origin */
  if(origin & CURLH_TRAILER) {
    printf("[TRAILER] ");
  }
  else if(origin & CURLH_1XX) {
    printf("[1XX] ");
  }
  else if(origin & CURLH_CONNECT) {
    printf("[CONNECT] ");
  }
  else if(origin & CURLH_PSEUDO) {
    printf("[PSEUDO] ");
  }
  else if(origin & CURLH_HEADER) {
    printf("[HEADER] ");
  }

  /* Print the header content (not null-terminated) */
  fwrite(buffer, size, nitems, stdout);

  return bytes;
}

int main(void)
{
  CURL *curl;
  CURLcode result;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Set the extended header callback that provides origin information */
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION_EXTENDED,
                     header_callback_ex);

    /* Perform the request */
    result = curl_easy_perform(curl);

    /* Check for errors */
    if(result != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return (int)result;
}
