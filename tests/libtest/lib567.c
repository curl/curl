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
#include "test.h"

#include "memdebug.h"

/*
 * Test a simple OPTIONS request with a custom header
 */
FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  struct fetch_slist *custom_headers = NULL;

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Dump data to stdout for protocol verification */
  test_setopt(fetch, FETCHOPT_HEADERDATA, stdout);
  test_setopt(fetch, FETCHOPT_WRITEDATA, stdout);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, URL);
  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_OPTIONS);
  test_setopt(fetch, FETCHOPT_USERAGENT, "test567");

  custom_headers = fetch_slist_append(custom_headers, "Test-Number: 567");
  test_setopt(fetch, FETCHOPT_RTSPHEADER, custom_headers);

  res = fetch_easy_perform(fetch);

test_cleanup:

  if(custom_headers)
    fetch_slist_free_all(custom_headers);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
