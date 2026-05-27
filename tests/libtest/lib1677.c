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

static const char t1677_data[] = "Hello Cloud!\n";
static size_t const t1677_datalen = sizeof(t1677_data) - 1;

struct t1677_headerinfo {
  unsigned int n_headers;
};

static size_t t1677_read_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t amount = nmemb * size; /* Total bytes curl wants */
  if(amount < t1677_datalen) {
    return t1677_datalen;
  }
  (void)stream;
  memcpy(ptr, t1677_data, t1677_datalen);
  return t1677_datalen;
}

static size_t header_extended(const char *ptr, size_t nmemb,
                              unsigned int origin, void *stream)
{
  struct t1677_headerinfo *info = (struct t1677_headerinfo *)stream;
  const char *origin_str;

  switch(origin) {
  case CURLH_HEADER:
    origin_str = "Header";
    break;
  case CURLH_TRAILER:
    origin_str = "Trailer";
    break;
  case CURLH_CONNECT:
    origin_str = "Connect";
    break;
  case CURLH_1XX:
    origin_str = "1xx";
    break;
  default:
    origin_str = "Unknown";
    break;
  }

  curl_mprintf("%s: ", origin_str);
  fwrite(ptr, 1, nmemb, stdout);

  info->n_headers++;

  return nmemb;
}

static CURLcode test_lib1677(const char *URL)
{
  CURL *curl = NULL;
  CURLcode code;
  CURLcode result = CURLE_OK;

  /* http header list */
  struct curl_slist *hhl = NULL, *tmp = NULL;

  struct t1677_headerinfo info = { 0 };

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  hhl = curl_slist_append(hhl, "User-Agent: Http Agent");
  if(!hhl) {
    goto test_cleanup;
  }
  tmp = curl_slist_append(hhl, "Expect: 100-continue");
  if(!tmp) {
    goto test_cleanup;
  }
  hhl = tmp;

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);
  easy_setopt(curl, CURLOPT_HTTPHEADER, hhl);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION_EXTENDED, header_extended);
  easy_setopt(curl, CURLOPT_HEADERDATA, &info);
  easy_setopt(curl, CURLOPT_POST, 0L);
  easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
  easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
  easy_setopt(curl, CURLOPT_READFUNCTION, t1677_read_cb);
  easy_setopt(curl, CURLOPT_INFILESIZE, (long)t1677_datalen);

  code = curl_easy_perform(curl);
  if(code != CURLE_OK) {
    curl_mfprintf(stderr, "%s:%d curl_easy_perform() failed, "
                  "with code %d (%s)\n",
                  __FILE__, __LINE__, code, curl_easy_strerror(code));
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  curl_mprintf("Total number of headers = %u\n", info.n_headers);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_slist_free_all(hhl);
  curl_global_cleanup();

  return result;
}
