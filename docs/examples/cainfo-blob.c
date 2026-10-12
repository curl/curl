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
 * Use CURLOPT_CAINFO_BLOB to provide a CA certificate bundle from memory.
 * </DESC>
 */
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

/* Replace with actual PEM-encoded CA certificate(s) */
static char ca_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB/TCCAZSgAwIBAgIUQ4hO7G+Z+7y4G+Q5fK1u0y2K3MwwCgYIKoZIzj0EAwIw\n"
  "EjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNDA5MDEwMDAwMDBaFw0zNDA5MDEwMDAw\n"
  "MDBaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n"
  "AARwS8N3R+W8d7a1q6Fz4e9j3H0q5r8s+2k6t1w5y4z8n0q2s3t4u5v6w7x8y9z0\n"
  "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUjCCAQUw\n"
  "DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU1234567890abcdef1234567890ab\n"
  "-----END CERTIFICATE-----\n";

int main(void)
{
  CURL *curl;
  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    struct curl_blob blob;

    /* Fill the curl_blob structure */
    blob.data = (void *)ca_pem;
    blob.len = strlen(ca_pem);
    blob.flags = CURL_BLOB_COPY;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Pass CA bundle from memory buffer */
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);

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
