/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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
#include "first.h"

#include "memdebug.h"

struct upload_status {
  int lines_read;
};

static size_t t1520_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  static const char *payload_text[] = {
    "From: different\r\n",
    "To: another\r\n",
    "\r\n",
    "\r\n",
    ".\r\n",
    ".\r\n",
    "\r\n",
    ".\r\n",
    "\r\n",
    "body",
    NULL
  };

  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;

  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }

  data = payload_text[upload_ctx->lines_read];

  if(data) {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    upload_ctx->lines_read++;

    return len;
  }

  return 0;
}

static CURLcode test_lib1520(const char *URL)
{
  CURLcode res;
  CURL *curl;
  struct curl_slist *rcpt_list = NULL;
  struct upload_status upload_ctx = {0};

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  rcpt_list = curl_slist_append(rcpt_list, "<recipient@example.com>");
#if 0
  /* more addresses can be added here */
  rcpt_list = curl_slist_append(rcpt_list, "<others@example.com>");
#endif
  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_READFUNCTION, t1520_read_cb);
  test_setopt(curl, CURLOPT_READDATA, &upload_ctx);
  test_setopt(curl, CURLOPT_MAIL_FROM, "<sender@example.com>");
  test_setopt(curl, CURLOPT_MAIL_RCPT, rcpt_list);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_slist_free_all(rcpt_list);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
