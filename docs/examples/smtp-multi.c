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
 * Send SMTP email with the multi interface
 * </DESC>
 */
#include <string.h>

#include <curl/curl.h>

/* This is an example showing how to send mail using libcurl's SMTP
 * capabilities. It builds on the smtp-mail.c example to demonstrate how to use
 * libcurl's multi interface.
 */

#define FROM_MAIL "<sender@example.com>"
#define TO_MAIL   "<recipient@example.com>"
#define CC_MAIL   "<info@example.com>"

static const char *payload_text =
  "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n"
  "To: " TO_MAIL "\r\n"
  "From: " FROM_MAIL "\r\n"
  "Cc: " CC_MAIL "\r\n"
  "Message-ID: <dcd7cb36-11db-487a-9f3a-e652a9458efd@"
  "rfcpedant.example.org>\r\n"
  "Subject: SMTP example message\r\n"
  "\r\n" /* empty line to divide headers from body, see RFC 5322 */
  "The body of the message starts here.\r\n"
  "\r\n"
  "It could be a lot of lines, could be MIME encoded, whatever.\r\n"
  "Check RFC 5322.\r\n";

struct upload_status {
  size_t bytes_read;
};

static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
  size_t room = size * nmemb;
  size_t len;

  if((size == 0) || (nmemb == 0) || ((size * nmemb) < 1)) {
    return 0;
  }

  data = &payload_text[upload_ctx->bytes_read];

  len = strlen(data);
  if(room < len)
    len = room;
  memcpy(ptr, data, len);
  upload_ctx->bytes_read += len;

  return len;
}

int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    CURLM *multi;

    multi = curl_multi_init();
    if(multi) {
      int still_running = 1;
      struct curl_slist *recipients = NULL;
      struct upload_status upload_ctx = { 0 };

      /* This is the URL for your mailserver */
      curl_easy_setopt(curl, CURLOPT_URL, "smtp://mail.example.com");

      /* Note that this option is not strictly required, omitting it results
       * in libcurl sending the MAIL FROM command with empty sender data. All
       * autoresponses should have an empty reverse-path, and should be
       * directed to the address in the reverse-path which triggered them.
       * Otherwise, they could cause an endless loop. See RFC 5321 Section
       * 4.5.5 for more details.
       */
      curl_easy_setopt(curl, CURLOPT_MAIL_FROM, FROM_MAIL);

      /* Add two recipients, in this particular case they correspond to the
       * To: and Cc: addressees in the header, but they could be any kind of
       * recipient. */
      recipients = curl_slist_append(recipients, TO_MAIL);
      recipients = curl_slist_append(recipients, CC_MAIL);
      curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

      /* We are using a callback function to specify the payload (the headers
       * and body of the message). You could just use the CURLOPT_READDATA
       * option to specify a FILE pointer to read from. */
      curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);
      curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

      /* Tell the multi stack about our easy handle */
      curl_multi_add_handle(multi, curl);

      do {
        CURLMcode mresult = curl_multi_perform(multi, &still_running);

        if(still_running)
          /* wait for activity, timeout or "nothing" */
          mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

        if(mresult)
          break;

      } while(still_running);

      /* Free the list of recipients */
      curl_slist_free_all(recipients);

      /* Always cleanup */
      curl_multi_remove_handle(multi, curl);
      curl_multi_cleanup(multi);
    }
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
