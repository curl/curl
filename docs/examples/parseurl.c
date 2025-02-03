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
/* <DESC>
 * Basic URL API use.
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

#if !FETCH_AT_LEAST_VERSION(7, 62, 0)
#error "this example requires fetch 7.62.0 or later"
#endif

int main(void)
{
  FETCHU *h;
  FETCHUcode uc;
  char *host;
  char *path;

  h = fetch_url(); /* get a handle to work with */
  if(!h)
    return 1;

  /* parse a full URL */
  uc = fetch_url_set(h, FETCHUPART_URL, "http://example.com/path/index.html", 0);
  if(uc)
    goto fail;

  /* extract hostname from the parsed URL */
  uc = fetch_url_get(h, FETCHUPART_HOST, &host, 0);
  if(!uc) {
    printf("Host name: %s\n", host);
    fetch_free(host);
  }

  /* extract the path from the parsed URL */
  uc = fetch_url_get(h, FETCHUPART_PATH, &path, 0);
  if(!uc) {
    printf("Path: %s\n", path);
    fetch_free(path);
  }

  /* redirect with a relative URL */
  uc = fetch_url_set(h, FETCHUPART_URL, "../another/second.html", 0);
  if(uc)
    goto fail;

  /* extract the new, updated path */
  uc = fetch_url_get(h, FETCHUPART_PATH, &path, 0);
  if(!uc) {
    printf("Path: %s\n", path);
    fetch_free(path);
  }

fail:
  fetch_url_cleanup(h); /* free URL handle */
  return 0;
}
