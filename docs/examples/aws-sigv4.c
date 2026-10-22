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
 * Get a resource from an S3 service using AWS SigV4 authentication.
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
    /* Set the S3 object URL */
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://mybucket.s3.us-east-1.amazonaws.example/"
                     "myphoto.jpg");

    /* Configure AWS SigV4: provider1:provider2:region:service */
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:us-east-1:s3");

    /* Supply the AWS Access Key ID and Secret Access Key */
    curl_easy_setopt(curl, CURLOPT_USERPWD,
                     "AKIAIOSFODNN7EXAMPLE:"
                     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

    result = curl_easy_perform(curl);
    if(result != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return (int)result;
}
