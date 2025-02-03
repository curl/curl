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
#include "test.h"

#include "memdebug.h"

/*
 * This is the list of basic details you need to tweak to get things right.
 */
#define TO "<recipient@example.com>"
#define FROM "<sender@example.com>"

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

struct upload_status {
  int lines_read;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
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

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  struct fetch_slist *rcpt_list = NULL;
  struct upload_status upload_ctx = {0};

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  rcpt_list = fetch_slist_append(rcpt_list, TO);
  /* more addresses can be added here
     rcpt_list = fetch_slist_append(rcpt_list, "<others@example.com>");
  */

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_UPLOAD, 1L);
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);
  test_setopt(fetch, FETCHOPT_READDATA, &upload_ctx);
  test_setopt(fetch, FETCHOPT_MAIL_FROM, FROM);
  test_setopt(fetch, FETCHOPT_MAIL_RCPT, rcpt_list);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_slist_free_all(rcpt_list);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
