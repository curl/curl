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
 * Send HTTP POST with trailing headers using CURLOPT_TRAILERFUNCTION.
 * </DESC>
 */
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

/* Callback invoked right before the final CRLF in chunked transfer */
static int trailer_cb(struct curl_slist **list, void *userdata)
{
  struct curl_slist *nlist;
  (void)userdata;

  /* Append the trailing header; libcurl frees the slist on completion */
  nlist = curl_slist_append(*list, "Checksum: 0123456789abcdef");
  if(!nlist)
    return CURL_TRAILERFUNC_ABORT;

  *list = nlist;
  return CURL_TRAILERFUNC_OK;
}

int main(void)
{
  CURL *curl;
  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    static const char post_data[] = "field1=value1&field2=value2";
    struct curl_slist *headers = NULL;
    struct curl_slist *nheaders;

    /* Declare expected trailers and force chunked transfer-encoding */
    nheaders = curl_slist_append(headers, "Trailer: Checksum");
    if(nheaders) {
      headers = nheaders;
      nheaders = curl_slist_append(headers, "Transfer-Encoding: chunked");
    }

    if(nheaders) {
      headers = nheaders;
      curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/upload");
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

      /* Configure the POST data */
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                       (long)sizeof(post_data) - 1);

      /* Set callback to populate trailing headers */
      curl_easy_setopt(curl, CURLOPT_TRAILERFUNCTION, trailer_cb);
      curl_easy_setopt(curl, CURLOPT_TRAILERDATA, NULL);

      result = curl_easy_perform(curl);
      if(result != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(result));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return (int)result;
}
