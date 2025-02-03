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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/* <DESC>
 * Send email on behalf of another user with SMTP
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

/*
 * This is a simple example show how to send an email using libfetch's SMTP
 * capabilities.
 *
 * Note that this example requires libfetch 7.66.0 or above.
 */

/* The libfetch options want plain addresses, the viewable headers in the mail
 * can get a full name as well.
 */
#define FROM_ADDR    "<ursel@example.org>"
#define SENDER_ADDR  "<kurt@example.org>"
#define TO_ADDR      "<addressee@example.net>"

#define FROM_MAIL    "Ursel " FROM_ADDR
#define SENDER_MAIL  "Kurt " SENDER_ADDR
#define TO_MAIL      "A Receiver " TO_ADDR

static const char *payload_text =
  "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n"
  "To: " TO_MAIL "\r\n"
  "From: " FROM_MAIL "\r\n"
  "Sender: " SENDER_MAIL "\r\n"
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

static size_t payload_source(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
  size_t room = size * nmemb;

  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }

  data = &payload_text[upload_ctx->bytes_read];

  if(data) {
    size_t len = strlen(data);
    if(room < len)
      len = room;
    memcpy(ptr, data, len);
    upload_ctx->bytes_read += len;

    return len;
  }

  return 0;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  struct fetch_slist *recipients = NULL;
  struct upload_status upload_ctx = { 0 };

  fetch = fetch_easy_init();
  if(fetch) {
    /* This is the URL for your mailserver. In this example we connect to the
       smtp-submission port as we require an authenticated connection. */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://mail.example.com:587");

    /* Set the username and password */
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "kurt");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "xipj3plmq");

    /* Set the authorization identity (identity to act as) */
    fetch_easy_setopt(fetch, FETCHOPT_SASL_AUTHZID, "ursel");

    /* Force PLAIN authentication */
    fetch_easy_setopt(fetch, FETCHOPT_LOGIN_OPTIONS, "AUTH=PLAIN");

    /* Note that this option is not strictly required, omitting it results in
     * libfetch sending the MAIL FROM command with empty sender data. All
     * autoresponses should have an empty reverse-path, and should be directed
     * to the address in the reverse-path which triggered them. Otherwise,
     * they could cause an endless loop. See RFC 5321 Section 4.5.5 for more
     * details.
     */
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_FROM, FROM_ADDR);

    /* Add a recipient, in this particular case it corresponds to the
     * To: addressee in the header. */
    recipients = fetch_slist_append(recipients, TO_ADDR);
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT, recipients);

    /* We are using a callback function to specify the payload (the headers and
     * body of the message). You could just use the FETCHOPT_READDATA option to
     * specify a FILE pointer to read from. */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, payload_source);
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, &upload_ctx);
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* Send the message */
    res = fetch_easy_perform(fetch);

    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* Free the list of recipients */
    fetch_slist_free_all(recipients);

    /* fetch does not send the QUIT command until you call cleanup, so you
     * should be able to reuse this connection for additional messages
     * (setting FETCHOPT_MAIL_FROM and FETCHOPT_MAIL_RCPT as required, and
     * calling fetch_easy_perform() again. It may not be a good idea to keep
     * the connection open for a long time though (more than a few minutes may
     * result in the server timing out the connection), and you do want to
     * clean up in the end.
     */
    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
