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

struct t3235_stats {
  size_t calls;
  size_t max_call;
  size_t total;
  int check_limit;
  int verify_pkt;
  int bad_data;
};

static size_t t3235_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
  struct t3235_stats *st = userdata;
  size_t n = size * nmemb;

  if(st->verify_pkt) {
    size_t i;
    for(i = 0; i < n; i++) {
      size_t pos = st->total + i;
      unsigned char expected;
      if(pos == 0)
        expected = '$';
      else if(pos == 1)
        expected = 0x00;
      else if(pos == 2)
        expected = 0x4e;
      else if(pos == 3)
        expected = 0x20;
      else if(pos < 20004)
        expected = 'A';
      else if(pos == 20004)
        expected = 'x';
      else
        expected = '\n';
      if((unsigned char)ptr[i] != expected) {
        st->bad_data = 1;
        break;
      }
    }
  }
  st->calls++;
  if(n > st->max_call)
    st->max_call = n;
  st->total += n;

  if(st->check_limit && (n > CURL_MAX_WRITE_SIZE)) {
    curl_mfprintf(stderr, "write callback exceeded CURL_MAX_WRITE_SIZE: "
                  "%zu > %d\n", n, CURL_MAX_WRITE_SIZE);
    return CURL_WRITEFUNC_ERROR;
  }
  return n;
}

static CURLcode t3235_do_options(CURL *curl, const char *URL, int part)
{
  CURLcode result;
  char *uri = tutil_suburl(URL, part);
  if(!uri)
    return TEST_ERR_MAJOR_BAD;

  result = curl_easy_setopt(curl, CURLOPT_URL, uri);
  if(!result)
    result = curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  if(!result)
    result = curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST,
                              CURL_RTSPREQ_OPTIONS);
  curl_free(uri);
  if(result)
    return result;

  return curl_easy_perform(curl);
}

static CURLcode test_lib3235(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  CURLcode perform_res;
  struct t3235_stats body_st;
  struct t3235_stats rtp_st;
  curl_off_t delivered = 0;
  curl_off_t dl = 0;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t3235_write_cb);
  easy_setopt(curl, CURLOPT_WRITEDATA, &body_st);
  easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

  /* Case 1: 20004-byte interleaved block via CURLOPT_WRITEFUNCTION must be
     chunked to at most CURL_MAX_WRITE_SIZE per call with intact payload. */
  memset(&body_st, 0, sizeof(body_st));
  body_st.check_limit = 1;
  body_st.verify_pkt = 1;
  easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, NULL);
  easy_setopt(curl, CURLOPT_MAXFILESIZE, 0L);

  result = t3235_do_options(curl, URL, 1);
  if(result)
    goto test_cleanup;

  result = curl_easy_getinfo(curl, CURLINFO_SIZE_DELIVERED, &delivered);
  if(!result)
    result = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &dl);
  if(result)
    goto test_cleanup;

  curl_mprintf("case1: calls=%zu max=%zu total=%zu bad=%d delivered=%"
               CURL_FORMAT_CURL_OFF_T " dl=%" CURL_FORMAT_CURL_OFF_T "\n",
               body_st.calls, body_st.max_call, body_st.total,
               body_st.bad_data, delivered, dl);

  /* Case 2: with CURLOPT_INTERLEAVEFUNCTION set, the full 20004-byte block
     must arrive in one call while the response body goes to write_cb. */
  memset(&body_st, 0, sizeof(body_st));
  memset(&rtp_st, 0, sizeof(rtp_st));
  body_st.check_limit = 1;
  easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, t3235_write_cb);
  easy_setopt(curl, CURLOPT_INTERLEAVEDATA, &rtp_st);
  easy_setopt(curl, CURLOPT_MAXFILESIZE, 0L);

  result = t3235_do_options(curl, URL, 2);
  if(result)
    goto test_cleanup;

  result = curl_easy_getinfo(curl, CURLINFO_SIZE_DELIVERED, &delivered);
  if(!result)
    result = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &dl);
  if(result)
    goto test_cleanup;

  curl_mprintf("case2: rtp_calls=%zu rtp_max=%zu rtp_total=%zu body=%zu "
               "delivered=%" CURL_FORMAT_CURL_OFF_T
               " dl=%" CURL_FORMAT_CURL_OFF_T "\n",
               rtp_st.calls, rtp_st.max_call, rtp_st.total, body_st.total,
               delivered, dl);

  /* Case 3: CURLOPT_MAXFILESIZE rejects an oversized interleaved block via
     CURLOPT_WRITEFUNCTION before delivering even a first chunk (limit is
     above CURL_MAX_WRITE_SIZE but below the 20004-byte block). */
  memset(&body_st, 0, sizeof(body_st));
  body_st.check_limit = 1;
  easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, NULL);
  easy_setopt(curl, CURLOPT_MAXFILESIZE, 18000L);

  perform_res = t3235_do_options(curl, URL, 3);
  curl_mprintf("case3: result=%d total=%zu\n", (int)perform_res,
               body_st.total);

  /* Case 4: CURLOPT_MAXFILESIZE rejects an oversized interleaved block via
     CURLOPT_INTERLEAVEFUNCTION before delivering any bytes of it. */
  memset(&body_st, 0, sizeof(body_st));
  memset(&rtp_st, 0, sizeof(rtp_st));
  body_st.check_limit = 1;
  easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, t3235_write_cb);
  easy_setopt(curl, CURLOPT_INTERLEAVEDATA, &rtp_st);
  easy_setopt(curl, CURLOPT_MAXFILESIZE, 10000L);

  perform_res = t3235_do_options(curl, URL, 4);
  curl_mprintf("case4: result=%d rtp_total=%zu body=%zu\n",
               (int)perform_res, rtp_st.total, body_st.total);

  /* Case 5: cumulative CURLOPT_MAXFILESIZE across multiple small blocks. */
  memset(&body_st, 0, sizeof(body_st));
  body_st.check_limit = 1;
  easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, NULL);
  easy_setopt(curl, CURLOPT_MAXFILESIZE, 1000L);

  perform_res = t3235_do_options(curl, URL, 5);
  result = curl_easy_getinfo(curl, CURLINFO_SIZE_DELIVERED, &delivered);
  if(!result)
    result = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &dl);
  if(result)
    goto test_cleanup;

  curl_mprintf("case5: result=%d calls=%zu total=%zu delivered=%"
               CURL_FORMAT_CURL_OFF_T " dl=%" CURL_FORMAT_CURL_OFF_T "\n",
               (int)perform_res, body_st.calls, body_st.total,
               delivered, dl);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
