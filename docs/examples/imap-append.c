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
 * Send email with IMAP
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to send mail using libfetch's IMAP
 * capabilities.
 *
 * Note that this example requires libfetch 7.30.0 or above.
 */

#define FROM "<sender@example.org>"
#define TO "<addressee@example.net>"
#define CC "<info@example.org>"

static const char *payload_text =
    "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n"
    "To: " TO "\r\n"
    "From: " FROM "(Example User)\r\n"
    "Cc: " CC "(Another example User)\r\n"
    "Message-ID: "
    "<dcd7cb36-11db-487a-9f3a-e652a9458efd@rfcpedant.example.org>\r\n"
    "Subject: IMAP example message\r\n"
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

  if (*data)
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
  FETCHcode res = FETCHE_OK;

  fetch = fetch_easy_init();
  if (fetch)
  {
    size_t filesize;
    long infilesize = LONG_MAX;
    struct upload_status upload_ctx = {0};

    /* Set username and password */
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "user");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "secret");

    /* This creates a new message in folder "Sent". */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "imap://imap.example.com/Sent");

    /* In this case, we are using a callback function to specify the data. You
     * could just use the FETCHOPT_READDATA option to specify a FILE pointer to
     * read from. */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, payload_source);
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, &upload_ctx);
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    filesize = strlen(payload_text);
    if (filesize <= LONG_MAX)
      infilesize = (long)filesize;
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE, infilesize);

    /* Perform the append */
    res = fetch_easy_perform(fetch);

    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* Always cleanup */
    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
