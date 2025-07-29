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

#include "memdebug.h"

static CURLcode test_lib653(const char *URL)
{
  CURL *curls = NULL;
  CURLcode res = CURLE_OK;
  curl_mimepart *field = NULL;
  curl_mime *mime = NULL;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curls);

  mime = curl_mime_init(curls);
  field = curl_mime_addpart(mime);
  curl_mime_name(field, "name");
  curl_mime_data(field, "short value", CURL_ZERO_TERMINATED);

  easy_setopt(curls, CURLOPT_URL, URL);
  easy_setopt(curls, CURLOPT_HEADER, 1L);
  easy_setopt(curls, CURLOPT_VERBOSE, 1L);
  easy_setopt(curls, CURLOPT_MIMEPOST, mime);
  easy_setopt(curls, CURLOPT_NOPROGRESS, 1L);

  res = curl_easy_perform(curls);
  if(res)
    goto test_cleanup;

  /* Alter form and resubmit. */
  curl_mime_data(field, "long value for length change", CURL_ZERO_TERMINATED);
  res = curl_easy_perform(curls);

test_cleanup:
  curl_mime_free(mime);
  curl_easy_cleanup(curls);
  curl_global_cleanup();
  return res; /* return the final return code */
}
