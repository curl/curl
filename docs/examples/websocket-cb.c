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
 * WebSocket download-only using write callback
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

static size_t writecb(char *b, size_t size, size_t nitems, void *p)
{
  CURL *easy = p;
  size_t i;
  const struct curl_ws_frame *frame = curl_ws_meta(easy);
  fprintf(stderr, "Type: %s\n", frame->flags & CURLWS_BINARY ?
          "binary" : "text");
  fprintf(stderr, "Bytes: %u", (unsigned int)(nitems * size));
  for(i = 0; i < nitems; i++)
    fprintf(stderr, "%02x ", (unsigned char)b[i]);
  return nitems;
}

int main(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "wss://example.com");

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecb);
    /* pass the easy handle to the callback */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
