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
#include "curlcheck.h"

#include <curl/curl.h>

static size_t print_httppost_callback(void *arg, const char *buf, size_t len)
{
  fwrite(buf, len, 1, stdout);
  (*(size_t *) arg) += len;
  return len;
}

CURLcode test(char *URL)
{
  CURLFORMcode rc;
  int res;
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = NULL;
  size_t total_size = 0;
  char buffer[] = "test buffer";

  CURL_IGNORE_DEPRECATION(
    rc = curl_formadd(&post, &last, CURLFORM_COPYNAME, "name",
                      CURLFORM_COPYCONTENTS, "content", CURLFORM_END);
  )
  fail_unless(rc == 0, "curl_formadd returned error");

  /* after the first curl_formadd when there's a single entry, both pointers
     should point to the same struct */
  fail_unless(post == last, "post and last weren't the same");

  CURL_IGNORE_DEPRECATION(
    rc = curl_formadd(&post, &last, CURLFORM_COPYNAME, "htmlcode",
                      CURLFORM_COPYCONTENTS, "<HTML></HTML>",
                      CURLFORM_CONTENTTYPE, "text/html", CURLFORM_END);
  )
  fail_unless(rc == 0, "curl_formadd returned error");

  CURL_IGNORE_DEPRECATION(
    rc = curl_formadd(&post, &last, CURLFORM_COPYNAME, "name_for_ptrcontent",
                     CURLFORM_PTRCONTENTS, buffer, CURLFORM_END);
  )
  fail_unless(rc == 0, "curl_formadd returned error");

  CURL_IGNORE_DEPRECATION(
    res = curl_formget(post, &total_size, print_httppost_callback);
  )
  fail_unless(res == 0, "curl_formget returned error");

  fail_unless(total_size == 518, "curl_formget got wrong size back");

  CURL_IGNORE_DEPRECATION(
    curl_formfree(post);
  )

  /* start a new formpost with a file upload and formget */
  post = last = NULL;

  CURL_IGNORE_DEPRECATION(
    rc = curl_formadd(&post, &last,
                      CURLFORM_PTRNAME, "name of file field",
                      CURLFORM_FILE, URL,
                      CURLFORM_FILENAME, "custom named file",
                      CURLFORM_END);
  )
  fail_unless(rc == 0, "curl_formadd returned error");

  CURL_IGNORE_DEPRECATION(
    res = curl_formget(post, &total_size, print_httppost_callback);
  )
  fail_unless(res == 0, "curl_formget returned error");
  fail_unless(total_size == 899, "curl_formget got wrong size back");

  CURL_IGNORE_DEPRECATION(
    curl_formfree(post);
  )
  return CURLE_OK;
}
