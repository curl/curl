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

FETCHcode test(char *URL)
{
  FETCH *eh = NULL;
  FETCHcode res = FETCHE_OK;
  struct fetch_httppost *lastptr = NULL;
  struct fetch_httppost *m_formpost = NULL;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(eh);

  easy_setopt(eh, FETCHOPT_URL, URL);
  FETCH_IGNORE_DEPRECATION(
      fetch_formadd(&m_formpost, &lastptr, FETCHFORM_COPYNAME, "file",
                    FETCHFORM_FILE, "missing-file", FETCHFORM_END);
      fetch_easy_setopt(eh, FETCHOPT_HTTPPOST, m_formpost);)

  (void)fetch_easy_perform(eh);
  (void)fetch_easy_perform(eh);

test_cleanup:

  FETCH_IGNORE_DEPRECATION(
      fetch_formfree(m_formpost);)
  fetch_easy_cleanup(eh);
  fetch_global_cleanup();

  return res;
}
