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
 * Send SMTP email with the multi interface
 * </DESC>
 */

#include <string.h>
#include <fetch/fetch.h>

/* This is an example showing how to send mail using libfetch's SMTP
 * capabilities. It builds on the smtp-mail.c example to demonstrate how to use
 * libfetch's multi interface.
 */

#define FROM_MAIL "<sender@example.com>"
#define TO_MAIL "<recipient@example.com>"
#define CC_MAIL "<info@example.com>"

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

struct upload_status
{
  size_t bytes_read;
};

static size_t payload_source(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
  size_t room = size * nmemb;

  if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1))
  {
    return 0;
  }

  data = &payload_text[upload_ctx->bytes_read];

  if (data)
  {
    size_t len = strlen(data);
    if (room < len)
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
  FETCHM *mfetch;
  int still_running = 1;
  struct fetch_slist *recipients = NULL;
  struct upload_status upload_ctx = {0};

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  fetch = fetch_easy_init();
  if (!fetch)
    return 1;

  mfetch = fetch_multi_init();
  if (!mfetch)
    return 2;

  /* This is the URL for your mailserver */
  fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://mail.example.com");

  /* Note that this option is not strictly required, omitting it results in
   * libfetch sending the MAIL FROM command with empty sender data. All
   * autoresponses should have an empty reverse-path, and should be directed
   * to the address in the reverse-path which triggered them. Otherwise, they
   * could cause an endless loop. See RFC 5321 Section 4.5.5 for more details.
   */
  fetch_easy_setopt(fetch, FETCHOPT_MAIL_FROM, FROM_MAIL);

  /* Add two recipients, in this particular case they correspond to the
   * To: and Cc: addressees in the header, but they could be any kind of
   * recipient. */
  recipients = fetch_slist_append(recipients, TO_MAIL);
  recipients = fetch_slist_append(recipients, CC_MAIL);
  fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT, recipients);

  /* We are using a callback function to specify the payload (the headers and
   * body of the message). You could just use the FETCHOPT_READDATA option to
   * specify a FILE pointer to read from. */
  fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, payload_source);
  fetch_easy_setopt(fetch, FETCHOPT_READDATA, &upload_ctx);
  fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

  /* Tell the multi stack about our easy handle */
  fetch_multi_add_handle(mfetch, fetch);

  do
  {
    FETCHMcode mc = fetch_multi_perform(mfetch, &still_running);

    if (still_running)
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_poll(mfetch, NULL, 0, 1000, NULL);

    if (mc)
      break;

  } while (still_running);

  /* Free the list of recipients */
  fetch_slist_free_all(recipients);

  /* Always cleanup */
  fetch_multi_remove_handle(mfetch, fetch);
  fetch_multi_cleanup(mfetch);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return 0;
}
