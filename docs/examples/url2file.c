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
/* <DESC>
 * Download a given URL into a local file named page.out.
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>

#include <fetch/fetch.h>

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int main(int argc, char *argv[])
{
  FETCH *fetch_handle;
  static const char *pagefilename = "page.out";
  FILE *pagefile;

  if(argc < 2) {
    printf("Usage: %s <URL>\n", argv[0]);
    return 1;
  }

  fetch_global_init(FETCH_GLOBAL_ALL);

  /* init the fetch session */
  fetch_handle = fetch_easy_init();

  /* set URL to get here */
  fetch_easy_setopt(fetch_handle, FETCHOPT_URL, argv[1]);

  /* Switch on full protocol/debug output while testing */
  fetch_easy_setopt(fetch_handle, FETCHOPT_VERBOSE, 1L);

  /* disable progress meter, set to 0L to enable it */
  fetch_easy_setopt(fetch_handle, FETCHOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
  fetch_easy_setopt(fetch_handle, FETCHOPT_WRITEFUNCTION, write_data);

  /* open the file */
  pagefile = fopen(pagefilename, "wb");
  if(pagefile) {

    /* write the page body to this file handle */
    fetch_easy_setopt(fetch_handle, FETCHOPT_WRITEDATA, pagefile);

    /* get it! */
    fetch_easy_perform(fetch_handle);

    /* close the header file */
    fclose(pagefile);
  }

  /* cleanup fetch stuff */
  fetch_easy_cleanup(fetch_handle);

  fetch_global_cleanup();

  return 0;
}
