/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include <stdio.h>
#include <curl/curl.h>

/* This is a simple example showing how to retrieve mail using libcurl's POP3
 * capabilities. It builds on the pop3-retr.c example adding transport
 * security to protect the authentication details from being snooped.
 *
 * Note that this example requires libcurl 7.20.0 or above.
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

    /* This will retreive message 1 from the user's mailbox */
    curl_easy_setopt(curl, CURLOPT_URL, "pop3://pop.example.com/1");

    /* In this example, we'll start with a plain text connection, and upgrade
     * to Transport Layer Security (TLS) using the STLS command. Be careful of
     * using CURLUSESSL_TRY here, because if TLS upgrade fails, the transfer
     * will continue anyway - see the security discussion in the libcurl
     * tutorial for more details. */
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

    /* If your server doesn't have a valid certificate, then you can disable
     * part of the Transport Layer Security protection by setting the
     * CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST options to 0 (false).
     *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
     *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
     * That is, in general, a bad idea. It is still better than sending your
     * authentication details in plain text though.
     * Instead, you should get the issuer certificate (or the host certificate
     * if the certificate is self-signed) and add it to the set of certificates
     * that are known to libcurl using CURLOPT_CAINFO and/or CURLOPT_CAPATH. See
     * docs/SSLCERTS for more information. */
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/certificate.pem");

    /* Since the traffic will be encrypted, it is very useful to turn on debug
     * information within libcurl to see what is happening during the
     * transfer */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Perform the retr */
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
