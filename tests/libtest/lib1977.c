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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURLU *curlu = curl_url();
  CURLU *curlu_2 = curl_url();
  CURL *curl;
  char *effective = NULL;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  /* first transfer: set just the URL in the first CURLU handle */
  curl_url_set(curlu, CURLUPART_URL, URL, CURLU_DEFAULT_SCHEME);
  easy_setopt(curl, CURLOPT_CURLU, curlu);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  effective = NULL;
  res = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective);
  if(res)
    goto test_cleanup;
  curl_mprintf("effective URL: %s\n", effective);


  /* second transfer: set URL + query in the second CURLU handle */
  curl_url_set(curlu_2, CURLUPART_URL, URL, CURLU_DEFAULT_SCHEME);
  curl_url_set(curlu_2, CURLUPART_QUERY, "foo", 0);
  easy_setopt(curl, CURLOPT_CURLU, curlu_2);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  effective = NULL;
  res = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective);
  if(res)
    goto test_cleanup;
  curl_mprintf("effective URL: %s\n", effective);


  /* third transfer: append extra query in the second CURLU handle, but do not
     set CURLOPT_CURLU again. this is to test that the contents of the handle
     is allowed to change between transfers and is used without having to set
     CURLOPT_CURLU again */
  curl_url_set(curlu_2, CURLUPART_QUERY, "bar", CURLU_APPENDQUERY);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  effective = NULL;
  res = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective);
  if(res)
    goto test_cleanup;
  curl_mprintf("effective URL: %s\n", effective);


test_cleanup:
  curl_easy_cleanup(curl);
  curl_url_cleanup(curlu);
  curl_url_cleanup(curlu_2);
  curl_global_cleanup();

  return res;
}
