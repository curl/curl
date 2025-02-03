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
 * Get a single file from an FTP server.
 * </DESC>
 */

struct FtpFile {
  const char *filename;
  FILE *stream;
};

static size_t my_fwrite(void *buffer, size_t size, size_t nmemb, void *stream)
{
  struct FtpFile *out = (struct FtpFile *)stream;
  if(!out->stream) {
    /* open file for writing */
    out->stream = fopen(out->filename, "wb");
    if(!out->stream)
      return 0; /* failure, cannot open file to write */
  }
  return fwrite(buffer, size, nmemb, out->stream);
}


int main(void)
{
  FETCH *fetch;
  FETCHcode res;
  struct FtpFile ftpfile = {
    "fetch.tar.gz", /* name to store the file as if successful */
    NULL
  };

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  fetch = fetch_easy_init();
  if(fetch) {
    /*
     * You better replace the URL with one that works!
     */
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "ftp://ftp.example.com/fetch/fetch-7.9.2.tar.gz");
    /* Define our callback to get called when there is data to be written */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, my_fwrite);
    /* Set a pointer to our struct to pass to the callback */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, &ftpfile);

    /* Switch on full protocol/debug output */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    res = fetch_easy_perform(fetch);

    /* always cleanup */
    fetch_easy_cleanup(fetch);

    if(FETCHE_OK != res) {
      /* we failed */
      fprintf(stderr, "fetch told us %d\n", res);
    }
  }

  if(ftpfile.stream)
    fclose(ftpfile.stream); /* close the local file */

  fetch_global_cleanup();

  return 0;
}
