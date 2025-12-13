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
#include "first.h"

struct t1485_transfer_status {
  CURL *curl;
  curl_off_t out_len;
  size_t hd_line;
  CURLcode res;
  int http_status;
};

static size_t t1485_header_callback(char *ptr, size_t size, size_t nmemb,
                                    void *userp)
{
  struct t1485_transfer_status *st = (struct t1485_transfer_status *)userp;
  const char *hd = ptr;
  size_t len = size * nmemb;
  CURLcode res;

  (void)fwrite(ptr, size, nmemb, stdout);
  ++st->hd_line;
  if(len == 2 && hd[0] == '\r' && hd[1] == '\n') {
    curl_off_t clen;
    long httpcode = 0;
    /* end of a response */
    res = curl_easy_getinfo(st->curl, CURLINFO_RESPONSE_CODE, &httpcode);
    curl_mfprintf(stderr, "header_callback, get status: %ld, %d\n",
                  httpcode, res);
    if(httpcode < 100 || httpcode >= 1000) {
      curl_mfprintf(stderr, "header_callback, invalid status: %ld, %d\n",
                    httpcode, res);
      return CURLE_WRITE_ERROR;
    }
    st->http_status = (int)httpcode;
    if(st->http_status >= 200 && st->http_status < 300) {
      res = curl_easy_getinfo(st->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                              &clen);
      curl_mfprintf(stderr, "header_callback, info Content-Length: "
                    "%" CURL_FORMAT_CURL_OFF_T ", %d\n", clen, res);
      if(res) {
        st->res = res;
        return CURLE_WRITE_ERROR;
      }
      if(clen < 0) {
        curl_mfprintf(stderr,
                      "header_callback, expected known Content-Length, "
                      "got: %" CURL_FORMAT_CURL_OFF_T "\n", clen);
        return CURLE_WRITE_ERROR;
      }
    }
  }
  return len;
}

static size_t t1485_write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t1485_transfer_status *st = (struct t1485_transfer_status *)userp;
  size_t len = size * nmemb;
  fwrite(ptr, size, nmemb, stdout);
  st->out_len += (curl_off_t)len;
  return len;
}

static CURLcode test_lib1485(const char *URL)
{
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  struct t1485_transfer_status st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);
  st.curl = curl; /* to allow callbacks access */

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t1485_write_cb);
  easy_setopt(curl, CURLOPT_WRITEDATA, &st);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, t1485_header_callback);
  easy_setopt(curl, CURLOPT_HEADERDATA, &st);

  easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res; /* return the final return code */
}
