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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCH *fetchs = NULL;
  FETCHcode res = FETCHE_OK;
  fetch_mimepart *field = NULL;
  fetch_mime *mime = NULL;

  global_init(FETCH_GLOBAL_ALL);
  easy_init(fetchs);

  mime = fetch_mime_init(fetchs);
  field = fetch_mime_addpart(mime);
  fetch_mime_name(field, "name");
  fetch_mime_data(field, "short value", FETCH_ZERO_TERMINATED);

  easy_setopt(fetchs, FETCHOPT_URL, URL);
  easy_setopt(fetchs, FETCHOPT_HEADER, 1L);
  easy_setopt(fetchs, FETCHOPT_VERBOSE, 1L);
  easy_setopt(fetchs, FETCHOPT_MIMEPOST, mime);
  easy_setopt(fetchs, FETCHOPT_NOPROGRESS, 1L);

  res = fetch_easy_perform(fetchs);
  if (res)
    goto test_cleanup;

  /* Alter form and resubmit. */
  fetch_mime_data(field, "long value for length change", FETCH_ZERO_TERMINATED);
  res = fetch_easy_perform(fetchs);

test_cleanup:
  fetch_mime_free(mime);
  fetch_easy_cleanup(fetchs);
  fetch_global_cleanup();
  return res; /* return the final return code */
}
