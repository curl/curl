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
#include "urldata.h"
#include "curl/urlapi.h"

static CURLcode test_lib1989(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  CURLU *u = NULL;
  CURLU *dup = NULL;
  CURLUcode uc;
  char *scheme = NULL;

  /* Parse a scheme-less URL, letting the scheme be guessed */
  u = curl_url();
  if(!u)
    goto fail;
  uc = curl_url_set(u, CURLUPART_URL, "example.com/path", CURLU_GUESS_SCHEME);
  fail_unless(uc == CURLUE_OK, "curl_url_set with CURLU_GUESS_SCHEME failed");

  /* The original handle should reject the scheme with CURLU_NO_GUESS_SCHEME
     since the scheme was only guessed, not explicit */
  uc = curl_url_get(u, CURLUPART_SCHEME, &scheme, CURLU_NO_GUESS_SCHEME);
  fail_unless(uc == CURLUE_NO_SCHEME,
              "original handle did not reject guessed scheme");
  curl_free(scheme);
  scheme = NULL;

  dup = curl_url_dup(u);
  if(!dup)
    goto fail;

  /* The duplicate must still remember that the scheme was guessed */
  uc = curl_url_get(dup, CURLUPART_SCHEME, &scheme, CURLU_NO_GUESS_SCHEME);
  fail_unless(uc == CURLUE_NO_SCHEME,
              "duplicated handle did not reject guessed scheme");
  curl_free(scheme);

fail:
  curl_url_cleanup(dup);
  curl_url_cleanup(u);

  UNITTEST_END_SIMPLE
}
