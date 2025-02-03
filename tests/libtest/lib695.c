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


/* write callback that does nothing */
static size_t write_it(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void) ptr;
  (void) userdata;
  return size * nmemb;
}

FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  fetch_mime *mime1 = NULL;
  fetch_mime *mime2 = NULL;
  fetch_mimepart *part;
  FETCHcode res = TEST_ERR_FAILURE;

  /*
   * Check proper rewind when reusing a mime structure.
   */

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();

  /* First set the URL that is about to receive our POST. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* Do not write anything. */
  fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_it);

  /* Build the first mime structure. */
  mime1 = fetch_mime_init(fetch);
  part = fetch_mime_addpart(mime1);
  fetch_mime_data(part, "<title>hello</title>", FETCH_ZERO_TERMINATED);
  fetch_mime_type(part, "text/html");
  fetch_mime_name(part, "data");

  /* Use first mime structure as top level MIME POST. */
  fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, mime1);

  /* Perform the request, res gets the return code */
  res = fetch_easy_perform(fetch);

  /* Check for errors */
  if(res != FETCHE_OK)
    fprintf(stderr, "fetch_easy_perform() 1 failed: %s\n",
            fetch_easy_strerror(res));
  else {
    /* phase two, create a mime struct using the mime1 handle */
    mime2 = fetch_mime_init(fetch);
    part = fetch_mime_addpart(mime2);

    /* use the new mime setup */
    fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, mime2);

    /* Reuse previous mime structure as a child. */
    res = fetch_mime_subparts(part, mime1);

    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_mime_subparts() failed: %sn",
              fetch_easy_strerror(res));
    else {
      mime1 = NULL;

      /* Perform the request, res gets the return code */
      res = fetch_easy_perform(fetch);

      /* Check for errors */
      if(res != FETCHE_OK)
        fprintf(stderr, "fetch_easy_perform() 2 failed: %s\n",
                fetch_easy_strerror(res));
    }
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_mime_free(mime1);
  fetch_mime_free(mime2);
  fetch_global_cleanup();
  return res;
}
