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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

struct transfer_status {
  FETCH *easy;
  fetch_off_t out_len;
  size_t hd_line;
  FETCHcode result;
  int http_status;
};

static size_t header_callback(char *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  const char *hd = ptr;
  size_t len = size * nmemb;
  FETCHcode result;

  (void)fwrite(ptr, size, nmemb, stdout);
  ++st->hd_line;
  if(len == 2 && hd[0] == '\r' && hd[1] == '\n') {
    fetch_off_t clen;
    long httpcode = 0;
    /* end of a response */
    result = fetch_easy_getinfo(st->easy, FETCHINFO_RESPONSE_CODE, &httpcode);
    fprintf(stderr, "header_callback, get status: %ld, %d\n",
            httpcode, result);
    if(httpcode < 100 || httpcode >= 1000) {
      fprintf(stderr, "header_callback, invalid status: %ld, %d\n",
              httpcode, result);
      return FETCHE_WRITE_ERROR;
    }
    st->http_status = (int)httpcode;
    if(st->http_status >= 200 && st->http_status < 300) {
      result = fetch_easy_getinfo(st->easy, FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T,
                                 &clen);
      fprintf(stderr, "header_callback, info Content-Length: %ld, %d\n",
              (long)clen, result);
      if(result) {
        st->result = result;
        return FETCHE_WRITE_ERROR;
      }
      if(clen < 0) {
        fprintf(stderr, "header_callback, expected known Content-Length, "
                "got: %ld\n", (long)clen);
        return FETCHE_WRITE_ERROR;
      }
    }
  }
  return len;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  size_t len = size * nmemb;
  fwrite(ptr, size, nmemb, stdout);
  st->out_len += (fetch_off_t)len;
  return len;
}

FETCHcode test(char *URL)
{
  FETCH *fetchs = NULL;
  FETCHcode res = FETCHE_OK;
  struct transfer_status st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetchs);
  st.easy = fetchs; /* to allow callbacks access */

  easy_setopt(fetchs, FETCHOPT_URL, URL);
  easy_setopt(fetchs, FETCHOPT_WRITEFUNCTION, write_callback);
  easy_setopt(fetchs, FETCHOPT_WRITEDATA, &st);
  easy_setopt(fetchs, FETCHOPT_HEADERFUNCTION, header_callback);
  easy_setopt(fetchs, FETCHOPT_HEADERDATA, &st);

  easy_setopt(fetchs, FETCHOPT_NOPROGRESS, 1L);

  res = fetch_easy_perform(fetchs);

test_cleanup:

  fetch_easy_cleanup(fetchs);
  fetch_global_cleanup();

  return res; /* return the final return code */
}
