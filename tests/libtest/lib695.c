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
#include "first.h"

#include "memdebug.h"

/* write callback that does nothing */
static size_t write_it(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static CURLcode test_lib695(const char *URL)
{
  CURL *curl = NULL;
  curl_mime *mime1 = NULL;
  curl_mime *mime2 = NULL;
  curl_mimepart *part;
  CURLcode res = TEST_ERR_FAILURE;

  /*
   * Check proper rewind when reusing a mime structure.
   */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* Do not write anything. */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_it);

  /* Build the first mime structure. */
  mime1 = curl_mime_init(curl);
  part = curl_mime_addpart(mime1);
  curl_mime_data(part, "<title>hello</title>", CURL_ZERO_TERMINATED);
  curl_mime_type(part, "text/html");
  curl_mime_name(part, "data");

  /* Use first mime structure as top level MIME POST. */
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime1);

  /* Perform the request, res gets the return code */
  res = curl_easy_perform(curl);

  /* Check for errors */
  if(res != CURLE_OK)
    curl_mfprintf(stderr, "curl_easy_perform() 1 failed: %s\n",
                  curl_easy_strerror(res));
  else {
    /* phase two, create a mime struct using the mime1 handle */
    mime2 = curl_mime_init(curl);
    part = curl_mime_addpart(mime2);

    /* use the new mime setup */
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime2);

    /* Reuse previous mime structure as a child. */
    res = curl_mime_subparts(part, mime1);

    if(res != CURLE_OK)
      curl_mfprintf(stderr, "curl_mime_subparts() failed: %sn",
                    curl_easy_strerror(res));
    else {
      mime1 = NULL;

      /* Perform the request, res gets the return code */
      res = curl_easy_perform(curl);

      /* Check for errors */
      if(res != CURLE_OK)
        curl_mfprintf(stderr, "curl_easy_perform() 2 failed: %s\n",
                      curl_easy_strerror(res));
    }
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_mime_free(mime1);
  curl_mime_free(mime2);
  curl_global_cleanup();
  return res;
}
