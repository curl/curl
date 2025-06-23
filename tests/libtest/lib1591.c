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

/*
 * This unit test PUT http data over proxy. Proxy header will be different
 * from server http header
 */

#include "first.h"

#include "memdebug.h"

static size_t consumed = 0;

static size_t t1591_read_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  static const char testdata[] = "Hello Cloud!\r\n";

  size_t amount = nmemb * size; /* Total bytes curl wants */

  if(consumed == strlen(testdata)) {
    return 0;
  }

  if(amount > strlen(testdata) - consumed) {
    amount = strlen(testdata);
  }

  consumed += amount;
  (void)stream;
  memcpy(ptr, testdata, amount);
  return amount;
}

/*
 * carefully not leak memory on OOM
 */
static int t1591_trailers_callback(struct curl_slist **list, void *userdata)
{
  struct curl_slist *nlist = NULL;
  struct curl_slist *nlist2 = NULL;
  (void)userdata;
  nlist = curl_slist_append(*list, "my-super-awesome-trailer: trail1");
  if(nlist)
    nlist2 = curl_slist_append(nlist, "my-other-awesome-trailer: trail2");
  if(nlist2) {
    *list = nlist2;
    return CURL_TRAILERFUNC_OK;
  }
  else {
    curl_slist_free_all(nlist);
    return CURL_TRAILERFUNC_ABORT;
  }
}

static CURLcode test_lib1591(char *URL)
{
  CURL *curl = NULL;
  CURLcode res = CURLE_FAILED_INIT;
  /* http and proxy header list */
  struct curl_slist *hhl = NULL;

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

  hhl = curl_slist_append(hhl, "Trailer: my-super-awesome-trailer,"
                               " my-other-awesome-trailer");
  if(!hhl) {
    goto test_cleanup;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HTTPHEADER, hhl);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_READFUNCTION, t1591_read_cb);
  test_setopt(curl, CURLOPT_TRAILERFUNCTION, t1591_trailers_callback);
  test_setopt(curl, CURLOPT_TRAILERDATA, NULL);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);

  curl_slist_free_all(hhl);

  curl_global_cleanup();

  return res;
}
