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

static CURLcode test_lib1921(const char *URL)
{
  CURLU *u = curl_url();
  CURLUcode rc;
  if(!u)
    return CURLE_FAILED_INIT;
  (void)URL; /* unused */
  /* u->scheme remains NULL */
  rc = curl_url_set(u, CURLUPART_HOST, "example.com", 0);
  if(!rc)
    rc = curl_url_set(u, CURLUPART_PATH, "/original", 0);

  if(!rc)
    /* Relative URL + CURLU_DEFAULT_SCHEME reaches redirect_url() */
    rc = curl_url_set(u, CURLUPART_URL, "/newpath", CURLU_DEFAULT_SCHEME);

  if(!rc) {
    char *url;
    rc = curl_url_get(u, CURLUPART_URL, &url, 0);
    if(!rc) {
      curl_mprintf("URL: %s\n", url);
      curl_free(url);
    }
  }
  curl_url_cleanup(u);
  return rc ? CURLE_BAD_FUNCTION_ARGUMENT : CURLE_OK;
}
