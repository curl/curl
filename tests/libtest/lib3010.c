/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Nicolas Sterchele, <nicolas@sterchelen.net>
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

FETCHcode test(char *URL)
{
  FETCHcode ret = FETCHE_OK;
  FETCH *fetch = NULL;
  fetch_off_t retry_after;
  char *follow_url = NULL;

  fetch_global_init(FETCH_GLOBAL_ALL);
  fetch = fetch_easy_init();

  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, URL);
    ret = fetch_easy_perform(fetch);
    if(ret) {
      fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
          __FILE__, __LINE__, ret, fetch_easy_strerror(ret));
      goto test_cleanup;
    }
    fetch_easy_getinfo(fetch, FETCHINFO_REDIRECT_URL, &follow_url);
    fetch_easy_getinfo(fetch, FETCHINFO_RETRY_AFTER, &retry_after);
    printf("Retry-After %" FETCH_FORMAT_FETCH_OFF_T "\n", retry_after);
    fetch_easy_setopt(fetch, FETCHOPT_URL, follow_url);
    ret = fetch_easy_perform(fetch);
    if(ret) {
      fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
          __FILE__, __LINE__, ret, fetch_easy_strerror(ret));
      goto test_cleanup;
    }

    fetch_easy_reset(fetch);
    fetch_easy_getinfo(fetch, FETCHINFO_RETRY_AFTER, &retry_after);
    printf("Retry-After %" FETCH_FORMAT_FETCH_OFF_T "\n", retry_after);
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return ret;
}
