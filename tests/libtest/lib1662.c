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
#include "test.h"

static char testdata[] = "mooaaa";

struct WriteThis
{
  size_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  size_t len = strlen(testdata);

  if (size * nmemb < len)
    return 0;

  if (pooh->sizeleft)
  {
    memcpy(ptr, testdata, strlen(testdata));
    pooh->sizeleft = 0;
    return len;
  }

  return 0; /* no more data left to deliver */
}

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *hnd;
  fetch_mime *mime1;
  fetch_mimepart *part1;
  struct WriteThis pooh = {1};

  mime1 = NULL;

  global_init(FETCH_GLOBAL_ALL);

  hnd = fetch_easy_init();
  if (hnd)
  {
    fetch_easy_setopt(hnd, FETCHOPT_BUFFERSIZE, 102400L);
    fetch_easy_setopt(hnd, FETCHOPT_URL, URL);
    fetch_easy_setopt(hnd, FETCHOPT_NOPROGRESS, 1L);
    mime1 = fetch_mime_init(hnd);
    if (mime1)
    {
      part1 = fetch_mime_addpart(mime1);
      fetch_mime_data_cb(part1, -1, read_callback, NULL, NULL, &pooh);
      fetch_mime_filename(part1, "poetry.txt");
      fetch_mime_name(part1, "content");
      fetch_easy_setopt(hnd, FETCHOPT_MIMEPOST, mime1);
      fetch_easy_setopt(hnd, FETCHOPT_USERAGENT, "fetch/2000");
      fetch_easy_setopt(hnd, FETCHOPT_FOLLOWLOCATION, 1L);
      fetch_easy_setopt(hnd, FETCHOPT_MAXREDIRS, 50L);
      fetch_easy_setopt(hnd, FETCHOPT_HTTP_VERSION,
                        (long)FETCH_HTTP_VERSION_2TLS);
      fetch_easy_setopt(hnd, FETCHOPT_VERBOSE, 1L);
      fetch_easy_setopt(hnd, FETCHOPT_FTP_SKIP_PASV_IP, 1L);
      fetch_easy_setopt(hnd, FETCHOPT_TCP_KEEPALIVE, 1L);
      res = fetch_easy_perform(hnd);
    }
  }

  fetch_easy_cleanup(hnd);
  fetch_mime_free(mime1);
  fetch_global_cleanup();
  return res;
}
