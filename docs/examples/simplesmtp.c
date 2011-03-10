/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <string.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *recipients = NULL;

  /* value for envelope reverse-path */
  static const char *from = "<bradh@example.com>";

  /* this becomes the envelope forward-path */
  static const char *to = "<bradh@example.net>";

  curl = curl_easy_init();
  if(curl) {
    /* this is the URL for your mailserver - you can also use an smtps:// URL
     * here */
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://mail.example.net.");

    /* Note that this option isn't strictly required, omitting it will result in
     * libcurl will sent the MAIL FROM command with no sender data. All
     * autoresponses should have an empty reverse-path, and should be directed
     * to the address in the reverse-path which triggered them. Otherwise, they
     * could cause an endless loop. See RFC 5321 Section 4.5.5 for more details.
     */
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);

    /* Note that the CURLOPT_MAIL_RCPT takes a list, not a char array.  */
    recipients = curl_slist_append(recipients, to);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    /* You provide the payload (headers and the body of the message) as the
     * "data" element. There are two choices, either:
     * - provide a callback function and specify the function name using the
     * CURLOPT_READFUNCTION option; or
     * - just provide a FILE pointer that can be used to read the data from.
     * The easiest case is just to read from standard input, (which is available
     * as a FILE pointer) as shown here.
     */
    curl_easy_setopt(curl, CURLOPT_READDATA, stdin);

    /* send the message (including headers) */
    res = curl_easy_perform(curl);

    /* free the list of recipients */
    curl_slist_free_all(recipients);

    /* curl won't send the QUIT command until you call cleanup, so you should be
     * able to re-use this connection for additional messages (setting
     * CURLOPT_MAIL_FROM and CURLOPT_MAIL_RCPT as required, and calling
     * curl_easy_perform() again. It may not be a good idea to keep the
     * connection open for a very long time though (more than a few minutes may
     * result in the server timing out the connection), and you do want to clean
     * up in the end.
     */
    curl_easy_cleanup(curl);
  }
  return 0;
}
