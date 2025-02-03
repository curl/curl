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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  char *url_after = NULL;
  FETCHU *fetchu = fetch_url();
  char error_buffer[FETCH_ERROR_SIZE] = "";
  FETCH *fetch;

  easy_init(fetch);

  fetch_url_set(fetchu, FETCHUPART_URL, URL, FETCHU_DEFAULT_SCHEME);
  easy_setopt(fetch, FETCHOPT_FETCHU, fetchu);
  easy_setopt(fetch, FETCHOPT_ERRORBUFFER, error_buffer);
  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  /* msys2 times out instead of FETCHE_COULDNT_CONNECT, so make it faster */
  easy_setopt(fetch, FETCHOPT_CONNECTTIMEOUT_MS, 5000L);
  /* set a port number that makes this request fail */
  easy_setopt(fetch, FETCHOPT_PORT, 1L);
  res = fetch_easy_perform(fetch);
  if (res != FETCHE_COULDNT_CONNECT && res != FETCHE_OPERATION_TIMEDOUT)
  {
    fprintf(stderr, "failure expected, "
                    "fetch_easy_perform returned %d: <%s>, <%s>\n",
            res, fetch_easy_strerror(res), error_buffer);
    if (res == FETCHE_OK)
      res = TEST_ERR_MAJOR_BAD; /* force an error return */
    goto test_cleanup;
  }
  res = FETCHE_OK; /* reset for next use */

  /* print the used url */
  fetch_url_get(fetchu, FETCHUPART_URL, &url_after, 0);
  fprintf(stderr, "fetchu now: <%s>\n", url_after);
  fetch_free(url_after);
  url_after = NULL;

  /* now reset FETCHOP_PORT to go back to originally set port number */
  easy_setopt(fetch, FETCHOPT_PORT, 0L);

  res = fetch_easy_perform(fetch);
  if (res)
    fprintf(stderr, "success expected, "
                    "fetch_easy_perform returned %d: <%s>, <%s>\n",
            res, fetch_easy_strerror(res), error_buffer);

  /* print url */
  fetch_url_get(fetchu, FETCHUPART_URL, &url_after, 0);
  fprintf(stderr, "fetchu now: <%s>\n", url_after);

test_cleanup:
  fetch_free(url_after);
  fetch_easy_cleanup(fetch);
  fetch_url_cleanup(fetchu);
  fetch_global_cleanup();

  return res;
}
