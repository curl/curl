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

#include "memdebug.h"

static const char *TEST_DATA_STRING = "Test data";
static int cb_count = 0;

static int
resolver_alloc_cb_fail(void *resolver_state, void *reserved, void *userdata)
{
  (void)resolver_state;
  (void)reserved;

  cb_count++;
  if(strcmp(userdata, TEST_DATA_STRING)) {
    fprintf(stderr, "Invalid test data received");
    exit(1);
  }

  return 1;
}

static int
resolver_alloc_cb_pass(void *resolver_state, void *reserved, void *userdata)
{
  (void)resolver_state;
  (void)reserved;

  cb_count++;
  if(strcmp(userdata, TEST_DATA_STRING)) {
    fprintf(stderr, "Invalid test data received");
    exit(1);
  }

  return 0;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our request. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  test_setopt(fetch, FETCHOPT_RESOLVER_START_DATA, TEST_DATA_STRING);
  test_setopt(fetch, FETCHOPT_RESOLVER_START_FUNCTION, resolver_alloc_cb_fail);

  /* this should fail */
  res = fetch_easy_perform(fetch);
  if(res != FETCHE_COULDNT_RESOLVE_HOST) {
    fprintf(stderr, "fetch_easy_perform should have returned "
            "FETCHE_COULDNT_RESOLVE_HOST but instead returned error %d\n", res);
    if(res == FETCHE_OK)
      res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_RESOLVER_START_FUNCTION, resolver_alloc_cb_pass);

  /* this should succeed */
  res = fetch_easy_perform(fetch);
  if(res) {
    fprintf(stderr, "fetch_easy_perform failed.\n");
    goto test_cleanup;
  }

  if(cb_count != 2) {
    fprintf(stderr, "Unexpected number of callbacks: %d\n", cb_count);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:
  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
