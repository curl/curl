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
#include <stdio.h>
#include <string.h>

#include <fetch/fetch.h>

/* <DESC>
 * Checks a single file's size and mtime from an FTP server.
 * </DESC>
 */

static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
  (void)ptr;
  (void)data;
  /* we are not interested in the headers itself,
     so we only return the size we would have saved ... */
  return (size_t)(size * nmemb);
}

int main(void)
{
  char ftpurl[] = "ftp://ftp.example.com/gnu/binutils/binutils-2.19.1.tar.bz2";
  FETCH *fetch;
  FETCHcode res;
  long filetime = -1;
  fetch_off_t filesize = 0;
  const char *filename = strrchr(ftpurl, '/') + 1;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, ftpurl);
    /* No download if the file */
    fetch_easy_setopt(fetch, FETCHOPT_NOBODY, 1L);
    /* Ask for filetime */
    fetch_easy_setopt(fetch, FETCHOPT_FILETIME, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_HEADERFUNCTION, throw_away);
    fetch_easy_setopt(fetch, FETCHOPT_HEADER, 0L);
    /* Switch on full protocol/debug output */
    /* fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L); */

    res = fetch_easy_perform(fetch);

    if (FETCHE_OK == res)
    {
      /* https://fetch.se/libfetch/c/fetch_easy_getinfo.html */
      res = fetch_easy_getinfo(fetch, FETCHINFO_FILETIME, &filetime);
      if ((FETCHE_OK == res) && (filetime >= 0))
      {
        time_t file_time = (time_t)filetime;
        printf("filetime %s: %s", filename, ctime(&file_time));
      }
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T,
                               &filesize);
      if ((FETCHE_OK == res) && (filesize > 0))
        printf("filesize %s: %" FETCH_FORMAT_FETCH_OFF_T " bytes\n",
               filename, filesize);
    }
    else
    {
      /* we failed */
      fprintf(stderr, "fetch told us %d\n", res);
    }

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }

  fetch_global_cleanup();

  return 0;
}
