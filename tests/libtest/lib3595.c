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

static CURLcode test_lib3595(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifndef CURL_DISABLE_MIME
  curl_mime *root = NULL;
  curl_mime *current = NULL;
  curl_mime *sub = NULL;
  curl_mimepart *part = NULL;
  int i;

  /* Create a deeply nested mime structure to verify that non-recursive
     curl_mime_free works properly. */
  (void)arg;
  root = curl_mime_init(NULL);
  fail_unless(root != NULL, "curl_mime_init root failed");
  current = root;

  for(i = 0; i < 50; i++) {
    part = curl_mime_addpart(current);
    fail_unless(part != NULL, "curl_mime_addpart failed");
    sub = curl_mime_init(NULL);
    fail_unless(sub != NULL, "curl_mime_init sub failed");
    curl_mime_subparts(part, sub);
    current = sub;
  }

  /* Free deep structure */
  curl_mime_free(root);
#else
  (void)arg;
#endif

  UNITTEST_END_SIMPLE
}
