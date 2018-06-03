/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
 * SMTP example showing how to send mime e-mails
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

/* This is a simple example showing how to send mime mail using libcurl's SMTP
 * capabilities. For an example of using the multi interface please see
 * smtp-multi.c.
 *
 * Note that this example requires libcurl 7.56.0 or above.
 */

#define FROM    "<sender@example.org>"
#define TO      "<addressee@example.net>"
#define CC      "<info@example.org>"

static const char *headers_text[] = {
  "Date: Tue, 22 Aug 2017 14:08:43 +0100",
  "To: " TO,
  "From: " FROM " (Example User)",
  "Cc: " CC " (Another example User)",
  "Message-ID: <dcd7cb36-11db-487a-9f3a-e652a9458efd@"
    "rfcpedant.example.org>",
  "Subject: example sending a MIME-formatted message",
  NULL
};

static const char inline_text[] =
  "This is the inline text message of the e-mail.\r\n"
  "\r\n"
  "  It could be a lot of lines that would be displayed in an e-mail\r\n"
  "viewer that is not able to handle HTML.\r\n";

static const char inline_html[] =
  "<html><body>\r\n"
  "<p>This is the inline <b>HTML</b> message of the e-mail.</p>"
  "<br />\r\n"
  "<p>It could be a lot of HTML data that would be displayed by "
  "e-mail viewers able to handle HTML.</p>"
  "</body></html>\r\n";


int main(void)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *headers = NULL;
  struct curl_slist *recipients = NULL;
  struct curl_slist *slist = NULL;
  curl_mime *mime;
  curl_mime *alt;
  curl_mimepart *part;
  const char **cpp;

  curl = curl_easy_init();
  if(curl) {
    /* This is the URL for your mailserver */
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://mail.example.com");

    /* Note that this option isn't strictly required, omitting it will result
     * in libcurl sending the MAIL FROM command with empty sender data. All
     * autoresponses should have an empty reverse-path, and should be directed
     * to the address in the reverse-path which triggered them. Otherwise,
     * they could cause an endless loop. See RFC 5321 Section 4.5.5 for more
     * details.
     */
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, FROM);

    /* Add two recipients, in this particular case they correspond to the
     * To: and Cc: addressees in the header, but they could be any kind of
     * recipient. */
    recipients = curl_slist_append(recipients, TO);
    recipients = curl_slist_append(recipients, CC);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    /* Build and set the message header list. */
    for(cpp = headers_text; *cpp; cpp++)
      headers = curl_slist_append(headers, *cpp);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Build the mime message. */
    mime = curl_mime_init(curl);

    /* The inline part is an alternative proposing the html and the text
       versions of the e-mail. */
    alt = curl_mime_init(curl);

    /* HTML message. */
    part = curl_mime_addpart(alt);
    curl_mime_data(part, inline_html, CURL_ZERO_TERMINATED);
    curl_mime_type(part, "text/html");

    /* Text message. */
    part = curl_mime_addpart(alt);
    curl_mime_data(part, inline_text, CURL_ZERO_TERMINATED);

    /* Create the inline part. */
    part = curl_mime_addpart(mime);
    curl_mime_subparts(part, alt);
    curl_mime_type(part, "multipart/alternative");
    slist = curl_slist_append(NULL, "Content-Disposition: inline");
    curl_mime_headers(part, slist, 1);

    /* Add the current source program as an attachment. */
    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, "smtp-mime.c");
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    /* Send the message */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* Free lists. */
    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);

    /* curl won't send the QUIT command until you call cleanup, so you should
     * be able to re-use this connection for additional messages (setting
     * CURLOPT_MAIL_FROM and CURLOPT_MAIL_RCPT as required, and calling
     * curl_easy_perform() again. It may not be a good idea to keep the
     * connection open for a very long time though (more than a few minutes
     * may result in the server timing out the connection), and you do want to
     * clean up in the end.
     */
    curl_easy_cleanup(curl);

    /* Free multipart message. */
    curl_mime_free(mime);
  }

  return (int)res;
}
