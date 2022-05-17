/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* <DESC>
 * Basic URL API use.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

#if !CURL_AT_LEAST_VERSION(7, 62, 0)
#error "this example requires curl 7.62.0 or later"
#endif

int main(void)
{
  CURLU *h;
  CURLUcode uc;
  char *host;
  char *path;

  h = curl_url(); /* get a handle to work with */
  if(!h)
    return 1;

  /* parse a full URL */
  uc = curl_url_set(h, CURLUPART_URL, "http://example.com/path/index.html", 0);
  if(uc)
    goto fail;

  /* extract host name from the parsed URL */
  uc = curl_url_get(h, CURLUPART_HOST, &host, 0);
  if(!uc) {
    printf("Host name: %s\n", host);
    curl_free(host);
  }

  /* extract the path from the parsed URL */
  uc = curl_url_get(h, CURLUPART_PATH, &path, 0);
  if(!uc) {
    printf("Path: %s\n", path);
    curl_free(path);
  }

  /* redirect with a relative URL */
  uc = curl_url_set(h, CURLUPART_URL, "../another/second.html", 0);
  if(uc)
    goto fail;

  /* extract the new, updated path */
  uc = curl_url_get(h, CURLUPART_PATH, &path, 0);
  if(!uc) {
    printf("Path: %s\n", path);
    curl_free(path);
  }

  fail:
  curl_url_cleanup(h); /* free url handle */
  return 0;
}
