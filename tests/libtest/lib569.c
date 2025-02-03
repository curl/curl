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

/*
 * Test Session ID capture
 */
FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  char *stream_uri = NULL;
  char *rtsp_session_id;
  int request = 1;
  int i;

  FILE *idfile = fopen(libtest_arg2, "wb");
  if(!idfile) {
    fprintf(stderr, "couldn't open the Session ID File\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_HEADERDATA, stdout);
  test_setopt(fetch, FETCHOPT_WRITEDATA, stdout);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  test_setopt(fetch, FETCHOPT_URL, URL);

  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_SETUP);
  res = fetch_easy_perform(fetch);
  if(res != (int)FETCHE_BAD_FUNCTION_ARGUMENT) {
    fprintf(stderr, "This should have failed. "
            "Cannot setup without a Transport: header");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Go through the various Session IDs */
  for(i = 0; i < 3; i++) {
    stream_uri = suburl(URL, request++);
    if(!stream_uri) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
    fetch_free(stream_uri);
    stream_uri = NULL;

    test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_SETUP);
    test_setopt(fetch, FETCHOPT_RTSP_TRANSPORT,
                "Fake/NotReal/JustATest;foo=baz");
    res = fetch_easy_perform(fetch);
    if(res)
      goto test_cleanup;

    fetch_easy_getinfo(fetch, FETCHINFO_RTSP_SESSION_ID, &rtsp_session_id);
    fprintf(idfile, "Got Session ID: [%s]\n", rtsp_session_id);
    rtsp_session_id = NULL;

    stream_uri = suburl(URL, request++);
    if(!stream_uri) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
    fetch_free(stream_uri);
    stream_uri = NULL;

    test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_TEARDOWN);
    res = fetch_easy_perform(fetch);

    /* Clear for the next go-round */
    test_setopt(fetch, FETCHOPT_RTSP_SESSION_ID, NULL);
  }

test_cleanup:

  if(idfile)
    fclose(idfile);

  fetch_free(stream_uri);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
