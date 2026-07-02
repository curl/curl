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
#include "unitcheck.h"
#include "urldata.h"
#include "mime.h"

#if !defined(CURL_DISABLE_MIME) && (!defined(CURL_DISABLE_HTTP) || \
    !defined(CURL_DISABLE_SMTP) || !defined(CURL_DISABLE_IMAP))

/* does any generated part header carry a raw CR or LF, i.e. a split line? */
static bool headers_have_ctrl(const curl_mimepart *part)
{
  const struct curl_slist *h;
  for(h = part->curlheaders; h; h = h->next)
    if(h->data[strcspn(h->data, "\r\n")])
      return TRUE;
  return FALSE;
}

static CURLcode test_unit3227(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  CURL *easy;
  curl_mime *mime;
  curl_mimepart *part;

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  abort_unless(easy, "curl_easy_init()");
  mime = curl_mime_init(easy);
  abort_unless(mime, "curl_mime_init()");

  /* A CR or LF in the mail-part name or filename would split the generated
     Content-Disposition header. The mail strategy must reject it. */

  part = curl_mime_addpart(mime);
  abort_unless(part, "curl_mime_addpart()");
  curl_mime_data(part, "x", 1);
  curl_mime_filename(part, "a\r\nX-Injected: 1");
  fail_unless(Curl_mime_prepare_headers(easy, part, NULL, NULL,
                                        MIMESTRATEGY_MAIL) ==
              CURLE_BAD_FUNCTION_ARGUMENT,
              "CRLF filename accepted for mail");

  part = curl_mime_addpart(mime);
  abort_unless(part, "curl_mime_addpart()");
  curl_mime_data(part, "x", 1);
  curl_mime_name(part, "a\nb");
  fail_unless(Curl_mime_prepare_headers(easy, part, NULL, NULL,
                                        MIMESTRATEGY_MAIL) ==
              CURLE_BAD_FUNCTION_ARGUMENT,
              "LF name accepted for mail");

  part = curl_mime_addpart(mime);
  abort_unless(part, "curl_mime_addpart()");
  curl_mime_data(part, "x", 1);
  curl_mime_filename(part, "a\rb");
  fail_unless(Curl_mime_prepare_headers(easy, part, NULL, NULL,
                                        MIMESTRATEGY_MAIL) ==
              CURLE_BAD_FUNCTION_ARGUMENT,
              "CR filename accepted for mail");

  /* A regular name and filename are accepted and produce a clean header. */
  part = curl_mime_addpart(mime);
  abort_unless(part, "curl_mime_addpart()");
  curl_mime_data(part, "x", 1);
  curl_mime_name(part, "field");
  curl_mime_filename(part, "readme.txt");
  fail_unless(Curl_mime_prepare_headers(easy, part, NULL, NULL,
                                        MIMESTRATEGY_MAIL) == CURLE_OK,
              "plain mail part rejected");
  fail_if(headers_have_ctrl(part), "clean mail header split");

  /* The HTTP form strategy percent-encodes CR/LF, so it stays accepted and
     produces no split line. */
  part = curl_mime_addpart(mime);
  abort_unless(part, "curl_mime_addpart()");
  curl_mime_data(part, "x", 1);
  curl_mime_filename(part, "a\r\nX-Injected: 1");
  fail_unless(Curl_mime_prepare_headers(easy, part, NULL, NULL,
                                        MIMESTRATEGY_FORM) == CURLE_OK,
              "CRLF filename rejected for form");
  fail_if(headers_have_ctrl(part), "form header split despite encoding");

  curl_mime_free(mime);
  curl_easy_cleanup(easy);
  curl_global_cleanup();

  UNITTEST_END(curl_global_cleanup())
}

#else /* mime disabled */

static CURLcode test_unit3227(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("nothing to do when mime is disabled");
  UNITTEST_END_SIMPLE
}

#endif
