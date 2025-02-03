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

#include <fetch/fetch.h>

/* <DESC>
 * Similar to ftpget.c but also stores the received response-lines
 * in a separate file using our own callback!
 * </DESC>
 */
static size_t
write_response(void *ptr, size_t size, size_t nmemb, void *data)
{
  FILE *writehere = (FILE *)data;
  return fwrite(ptr, size, nmemb, writehere);
}

#define FTPBODY "ftp-list"
#define FTPHEADERS "ftp-responses"

int main(void)
{
  FETCH *fetch;
  FETCHcode res;
  FILE *ftpfile;
  FILE *respfile;

  /* local filename to store the file as */
  ftpfile = fopen(FTPBODY, "wb"); /* b is binary, needed on Windows */
  if(!ftpfile)
    return 1;

  /* local filename to store the FTP server's response lines in */
  respfile = fopen(FTPHEADERS, "wb"); /* b is binary, needed on Windows */
  if(!respfile) {
    fclose(ftpfile);
    return 1;
  }

  fetch = fetch_easy_init();
  if(fetch) {
    /* Get a file listing from sunet */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://ftp.example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, ftpfile);
    /* If you intend to use this on Windows with a libfetch DLL, you must use
       FETCHOPT_WRITEFUNCTION as well */
    fetch_easy_setopt(fetch, FETCHOPT_HEADERFUNCTION, write_response);
    fetch_easy_setopt(fetch, FETCHOPT_HEADERDATA, respfile);
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }

  fclose(ftpfile); /* close the local file */
  fclose(respfile); /* close the response file */

  return 0;
}
