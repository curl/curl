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

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch = NULL;
  char *newURL = NULL;
  struct fetch_slist *slist = NULL;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* test: FETCHFTPMETHOD_SINGLECWD with absolute path should
           skip CWD to entry path */
  newURL = aprintf("%s/folderA/661", URL);
  test_setopt(fetch, FETCHOPT_URL, newURL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_IGNORE_CONTENT_LENGTH, 1L);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_SINGLECWD);
  res = fetch_easy_perform(fetch);
  if (res != FETCHE_REMOTE_FILE_NOT_FOUND)
    goto test_cleanup;

  fetch_free(newURL);
  newURL = aprintf("%s/folderB/661", URL);
  test_setopt(fetch, FETCHOPT_URL, newURL);
  res = fetch_easy_perform(fetch);
  if (res != FETCHE_REMOTE_FILE_NOT_FOUND)
    goto test_cleanup;

  /* test: FETCHFTPMETHOD_NOCWD with absolute path should
     never emit CWD (for both new and reused easy handle) */
  fetch_easy_cleanup(fetch);
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  fetch_free(newURL);
  newURL = aprintf("%s/folderA/661", URL);
  test_setopt(fetch, FETCHOPT_URL, newURL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_IGNORE_CONTENT_LENGTH, 1L);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_NOCWD);
  res = fetch_easy_perform(fetch);
  if (res != FETCHE_REMOTE_FILE_NOT_FOUND)
    goto test_cleanup;

  /* curve ball: CWD /folderB before reusing connection with _NOCWD */
  fetch_free(newURL);
  newURL = aprintf("%s/folderB/661", URL);
  test_setopt(fetch, FETCHOPT_URL, newURL);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_SINGLECWD);
  res = fetch_easy_perform(fetch);
  if (res != FETCHE_REMOTE_FILE_NOT_FOUND)
    goto test_cleanup;

  fetch_free(newURL);
  newURL = aprintf("%s/folderA/661", URL);
  test_setopt(fetch, FETCHOPT_URL, newURL);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_NOCWD);
  res = fetch_easy_perform(fetch);
  if (res != FETCHE_REMOTE_FILE_NOT_FOUND)
    goto test_cleanup;

  /* test: FETCHFTPMETHOD_NOCWD with home-relative path should
     not emit CWD for first FTP access after login */
  fetch_easy_cleanup(fetch);
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  slist = fetch_slist_append(NULL, "SYST");
  if (!slist)
  {
    fprintf(stderr, "fetch_slist_append() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_NOBODY, 1L);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_NOCWD);
  test_setopt(fetch, FETCHOPT_QUOTE, slist);
  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  /* test: FETCHFTPMETHOD_SINGLECWD with home-relative path should
     not emit CWD for first FTP access after login */
  fetch_easy_cleanup(fetch);
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_NOBODY, 1L);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_SINGLECWD);
  test_setopt(fetch, FETCHOPT_QUOTE, slist);
  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  /* test: FETCHFTPMETHOD_NOCWD with home-relative path should
     not emit CWD for second FTP access when not needed +
     bonus: see if path buffering survives fetch_easy_reset() */
  fetch_easy_reset(fetch);
  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_NOBODY, 1L);
  test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long)FETCHFTPMETHOD_NOCWD);
  test_setopt(fetch, FETCHOPT_QUOTE, slist);
  res = fetch_easy_perform(fetch);

test_cleanup:

  if (res)
    fprintf(stderr, "test encountered error %d\n", res);
  fetch_slist_free_all(slist);
  fetch_free(newURL);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
