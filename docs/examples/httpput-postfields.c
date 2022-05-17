/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * HTTP PUT using CURLOPT_POSTFIELDS
 * </DESC>
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>

static const char olivertwist[]=
  "Among other public buildings in a certain town, which for many reasons "
  "it will be prudent to refrain from mentioning, and to which I will assign "
  "no fictitious name, there is one anciently common to most towns, great or "
  "small: to wit, a workhouse; and in this workhouse was born; on a day and "
  "date which I need not trouble myself to repeat, inasmuch as it can be of "
  "no possible consequence to the reader, in this stage of the business at "
  "all events; the item of mortality whose name is prefixed to the head of "
  "this chapter.";

/*
 * This example shows a HTTP PUT operation that sends a fixed buffer with
 * CURLOPT_POSTFIELDS to the URL given as an argument.
 */

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;
  char *url;

  if(argc < 2)
    return 1;

  url = argv[1];

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;

    /* default type with postfields is application/x-www-form-urlencoded,
       change it if you want */
    headers = curl_slist_append(headers, "Content-Type: literature/classic");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* pass on content in request body. When CURLOPT_POSTFIELDSIZE is not used,
       curl does strlen to get the size. */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, olivertwist);

    /* override the POST implied by CURLOPT_POSTFIELDS
     *
     * Warning: CURLOPT_CUSTOMREQUEST is problematic, especially if you want
     * to follow redirects. Be aware.
     */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

    /* specify target URL, and note that this URL should include a file
       name, not only a directory */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* Now run off and do what you have been told! */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* free headers */
    curl_slist_free_all(headers);
  }

  curl_global_cleanup();
  return 0;
}
