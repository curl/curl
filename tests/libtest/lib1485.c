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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

struct transfer_status {
  CURL *easy;
  curl_off_t out_len;
  size_t hd_line;
  CURLcode result;
  int http_status;
};

static size_t header_callback(char *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  const char *hd = ptr;
  size_t len = size * nmemb;
  CURLcode result;

  (void)fwrite(ptr, size, nmemb, stdout);
  ++st->hd_line;
  if(len == 2 && hd[0] == '\r' && hd[1] == '\n') {
    curl_off_t clen;
    long httpcode = 0;
    /* end of a response */
    result = curl_easy_getinfo(st->easy, CURLINFO_RESPONSE_CODE, &httpcode);
    curl_mfprintf(stderr, "header_callback, get status: %ld, %d\n",
                  httpcode, result);
    if(httpcode < 100 || httpcode >= 1000) {
      curl_mfprintf(stderr, "header_callback, invalid status: %ld, %d\n",
                    httpcode, result);
      return CURLE_WRITE_ERROR;
    }
    st->http_status = (int)httpcode;
    if(st->http_status >= 200 && st->http_status < 300) {
      result = curl_easy_getinfo(st->easy, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                                 &clen);
      curl_mfprintf(stderr, "header_callback, info Content-Length: %ld, %d\n",
                    (long)clen, result);
      if(result) {
        st->result = result;
        return CURLE_WRITE_ERROR;
      }
      if(clen < 0) {
        curl_mfprintf(stderr,
                      "header_callback, expected known Content-Length, "
                      "got: %ld\n", (long)clen);
        return CURLE_WRITE_ERROR;
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
  st->out_len += (curl_off_t)len;
  return len;
}

CURLcode test(char *URL)
{
  CURL *curls = NULL;
  CURLcode res = CURLE_OK;
  struct transfer_status st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);

  easy_init(curls);
  st.easy = curls; /* to allow callbacks access */

  easy_setopt(curls, CURLOPT_URL, URL);
  easy_setopt(curls, CURLOPT_WRITEFUNCTION, write_callback);
  easy_setopt(curls, CURLOPT_WRITEDATA, &st);
  easy_setopt(curls, CURLOPT_HEADERFUNCTION, header_callback);
  easy_setopt(curls, CURLOPT_HEADERDATA, &st);

  easy_setopt(curls, CURLOPT_NOPROGRESS, 1L);

  res = curl_easy_perform(curls);

test_cleanup:

  curl_easy_cleanup(curls);
  curl_global_cleanup();

  return res; /* return the final return code */
}
