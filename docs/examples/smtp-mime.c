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
 * Send SMTP mime emails
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to send mime mail using libfetch's SMTP
 * capabilities. For an example of using the multi interface please see
 * smtp-multi.c.
 *
 * Note that this example requires libfetch 7.56.0 or above.
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
  "This is the inline text message of the email.\r\n"
  "\r\n"
  "  It could be a lot of lines that would be displayed in an email\r\n"
  "viewer that is not able to handle HTML.\r\n";

static const char inline_html[] =
  "<html><body>\r\n"
  "<p>This is the inline <b>HTML</b> message of the email.</p>"
  "<br />\r\n"
  "<p>It could be a lot of HTML data that would be displayed by "
  "email viewers able to handle HTML.</p>"
  "</body></html>\r\n";


int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_slist *headers = NULL;
    struct fetch_slist *recipients = NULL;
    struct fetch_slist *slist = NULL;
    fetch_mime *mime;
    fetch_mime *alt;
    fetch_mimepart *part;
    const char **cpp;

    /* This is the URL for your mailserver */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://mail.example.com");

    /* Note that this option is not strictly required, omitting it results in
     * libfetch sending the MAIL FROM command with empty sender data. All
     * autoresponses should have an empty reverse-path, and should be directed
     * to the address in the reverse-path which triggered them. Otherwise,
     * they could cause an endless loop. See RFC 5321 Section 4.5.5 for more
     * details.
     */
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_FROM, FROM);

    /* Add two recipients, in this particular case they correspond to the
     * To: and Cc: addressees in the header, but they could be any kind of
     * recipient. */
    recipients = fetch_slist_append(recipients, TO);
    recipients = fetch_slist_append(recipients, CC);
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT, recipients);

    /* allow one of the recipients to fail and still consider it okay */
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT_ALLOWFAILS, 1L);

    /* Build and set the message header list. */
    for(cpp = headers_text; *cpp; cpp++)
      headers = fetch_slist_append(headers, *cpp);
    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headers);

    /* Build the mime message. */
    mime = fetch_mime_init(fetch);

    /* The inline part is an alternative proposing the html and the text
       versions of the email. */
    alt = fetch_mime_init(fetch);

    /* HTML message. */
    part = fetch_mime_addpart(alt);
    fetch_mime_data(part, inline_html, FETCH_ZERO_TERMINATED);
    fetch_mime_type(part, "text/html");

    /* Text message. */
    part = fetch_mime_addpart(alt);
    fetch_mime_data(part, inline_text, FETCH_ZERO_TERMINATED);

    /* Create the inline part. */
    part = fetch_mime_addpart(mime);
    fetch_mime_subparts(part, alt);
    fetch_mime_type(part, "multipart/alternative");
    slist = fetch_slist_append(NULL, "Content-Disposition: inline");
    fetch_mime_headers(part, slist, 1);

    /* Add the current source program as an attachment. */
    part = fetch_mime_addpart(mime);
    fetch_mime_filedata(part, "smtp-mime.c");
    fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, mime);

    /* Send the message */
    res = fetch_easy_perform(fetch);

    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* Free lists. */
    fetch_slist_free_all(recipients);
    fetch_slist_free_all(headers);

    /* fetch does not send the QUIT command until you call cleanup, so you
     * should be able to reuse this connection for additional messages
     * (setting FETCHOPT_MAIL_FROM and FETCHOPT_MAIL_RCPT as required, and
     * calling fetch_easy_perform() again. It may not be a good idea to keep
     * the connection open for a long time though (more than a few minutes may
     * result in the server timing out the connection), and you do want to
     * clean up in the end.
     */
    fetch_easy_cleanup(fetch);

    /* Free multipart message. */
    fetch_mime_free(mime);
  }

  return (int)res;
}
