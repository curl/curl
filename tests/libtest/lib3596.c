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
#include "unitcheck.h"

#if !defined(CURL_DISABLE_MIME) && !defined(CURL_DISABLE_HTTP)
static int callback_free_count = 0;

static void test_cb_free(void *ptr)
{
  (void)ptr;
  callback_free_count++;
}

static size_t test_cb_read(char *buffer, size_t size, size_t nitems, void *arg)
{
  (void)buffer;
  (void)size;
  (void)nitems;
  (void)arg;
  return 0;
}
#endif

static CURLcode test_lib3596(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_MIME) && !defined(CURL_DISABLE_HTTP)

  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  curl_mime *root = NULL;
  curl_mime *current = NULL;
  curl_mime *sub = NULL;
  curl_mimepart *part = NULL;
  int i;

  callback_free_count = 0;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  fail_unless(curl != NULL, "curl_easy_init() failed");

  /* Create a deeper than MAX_MIME_LEVELS nested mime structure to verify
     that header preparation bounds recursion instead of exhausting the
     stack. */
  root = curl_mime_init(curl);
  fail_unless(root != NULL, "curl_mime_init root failed");

  /* Add a sibling part with a custom free callback before the deep chain
     to verify that preflight depth rejection does not duplicate callbacks
     or invoke them during error rollback. */
  part = curl_mime_addpart(root);
  fail_unless(part != NULL, "curl_mime_addpart sibling failed");
  result = curl_mime_data_cb(part, 0, test_cb_read, NULL, test_cb_free, NULL);
  fail_unless(result == CURLE_OK, "curl_mime_data_cb failed");

  current = root;

  for(i = 0; i < 50; i++) {
    part = curl_mime_addpart(current);
    fail_unless(part != NULL, "curl_mime_addpart failed");
    sub = curl_mime_init(curl);
    fail_unless(sub != NULL, "curl_mime_init sub failed");
    curl_mime_subparts(part, sub);
    current = sub;
  }

  result = curl_easy_setopt(curl, CURLOPT_URL, arg);
  fail_unless(result == CURLE_OK, "CURLOPT_URL failed");
  if(!result)
    result = curl_easy_setopt(curl, CURLOPT_MIMEPOST, root);
  fail_unless(result == CURLE_OK, "CURLOPT_MIMEPOST failed");

  /* Deep nesting must fail gracefully (CURLE_TOO_LARGE), not crash, and
     must not invoke copied user free callbacks during error rollback. */
  if(!result) {
    CURL *dup = curl_easy_duphandle(curl);
    fail_unless(dup == NULL,
                "curl_easy_duphandle unexpectedly succeeded for nested mime");
    fail_unless(callback_free_count == 0,
                "free callback invoked during failed duphandle rollback");
  }

  if(!result)
    result = curl_easy_perform(curl);
  fail_unless(result == CURLE_TOO_LARGE,
              "deeply nested mime did not fail with CURLE_TOO_LARGE");

  {
    CURL *dup = curl_easy_duphandle(curl);
    fail_unless(dup == NULL,
                "curl_easy_duphandle unexpectedly succeeded after perform");
    fail_unless(callback_free_count == 0,
                "free callback invoked after perform duphandle");
  }

  curl_easy_cleanup(curl);
  curl_mime_free(root);
  fail_unless(callback_free_count == 1,
              "free callback not invoked during root cleanup");
  curl_global_cleanup();
#else
  (void)arg;
#endif

  UNITTEST_END_SIMPLE
}
