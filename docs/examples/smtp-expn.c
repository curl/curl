/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

/* <DESC>
 * SMTP example showing how to expand an email mailing list
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

/* This is a simple example showing how to expand an email mailing list.
 *
 * Notes:
 *
 * 1) This example requires libcurl 7.34.0 or above.
 * 2) Not all email servers support this command.
 */

int main(void)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *recipients = NULL;

  curl = curl_easy_init();
  if(curl) {
    /* This is the URL for your mailserver */
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://mail.example.com");

    /* Note that the CURLOPT_MAIL_RCPT takes a list, not a char array  */
    recipients = curl_slist_append(recipients, "Friends");
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    /* Set the EXPN command */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "EXPN");

    /* Perform the custom request */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* Free the list of recipients */
    curl_slist_free_all(recipients);

    /* curl will not send the QUIT command until you call cleanup, so you
     * should be able to re-use this connection for additional requests. It
     * may not be a good idea to keep the connection open for a very long time
     * though (more than a few minutes may result in the server timing out the
     * connection) and you do want to clean up in the end.
     */
    curl_easy_cleanup(curl);
  }

  return 0;
}
