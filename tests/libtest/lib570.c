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

/* build request url */
static char *suburl(const char *base, int i)
{
  return fetch_maprintf("%s%.4d", base, i);
}

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  int request = 1;
  char *stream_uri = NULL;

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

  test_setopt(fetch, FETCHOPT_HEADERDATA, stdout);
  test_setopt(fetch, FETCHOPT_WRITEDATA, stdout);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  test_setopt(fetch, FETCHOPT_URL, URL);

  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_OPTIONS);

  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;

  res = fetch_easy_perform(fetch);
  if(res != (int)FETCHE_RTSP_CSEQ_ERROR) {
    fprintf(stderr, "Failed to detect CSeq mismatch");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_RTSP_CLIENT_CSEQ, 999L);
  test_setopt(fetch, FETCHOPT_RTSP_TRANSPORT,
                    "RAW/RAW/UDP;unicast;client_port=3056-3057");
  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_SETUP);

  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;

  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_PLAY);

  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;

  res = fetch_easy_perform(fetch);
  if(res == FETCHE_RTSP_SESSION_ERROR) {
    res = FETCHE_OK;
  }
  else {
    fprintf(stderr, "Failed to detect a Session ID mismatch");
    res = (FETCHcode)1;
  }

test_cleanup:
  fetch_free(stream_uri);

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
