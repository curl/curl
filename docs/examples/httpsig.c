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
 * Send an HTTP request signed with RFC 9421 HTTP Message Signatures.
 * </DESC>
 */
#include <stdio.h>

#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;

    /* Add a custom header that gets signed */
    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if(headers) {
      curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/api");
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

      /* Select signing algorithm (e.g. Ed25519) */
      curl_easy_setopt(curl, CURLOPT_HTTPSIG_ALGORITHM, CURLHTTPSIG_ED25519);

      /* Hex-encoded 32-byte Ed25519 seed */
      curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEY,
                       "9f8362f87a484a954e6e740c5b4c0e84"
                       "229139a20aa8ab56ff66586f6a7d29c5");

      /* Key identifier sent in Signature-Input */
      curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEYID, "my-key-id");

      /* Components and headers to include in the signature */
      curl_easy_setopt(curl, CURLOPT_HTTPSIG_HEADERS,
                       "method authority path content-type:");

      result = curl_easy_perform(curl);
      if(result != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(result));

      curl_slist_free_all(headers);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return (int)result;
}
