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
/* <DESC>
 * Simple HTTP GET that stores the headers in a separate file
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

int main(void)
{
  FETCH *fetch_handle;
  static const char *headerfilename = "head.out";
  FILE *headerfile;
  static const char *bodyfilename = "body.out";
  FILE *bodyfile;

  fetch_global_init(FETCH_GLOBAL_ALL);

  /* init the fetch session */
  fetch_handle = fetch_easy_init();

  /* set URL to get */
  fetch_easy_setopt(fetch_handle, FETCHOPT_URL, "https://example.com");

  /* no progress meter please */
  fetch_easy_setopt(fetch_handle, FETCHOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
  fetch_easy_setopt(fetch_handle, FETCHOPT_WRITEFUNCTION, write_data);

  /* open the header file */
  headerfile = fopen(headerfilename, "wb");
  if (!headerfile)
  {
    fetch_easy_cleanup(fetch_handle);
    return -1;
  }

  /* open the body file */
  bodyfile = fopen(bodyfilename, "wb");
  if (!bodyfile)
  {
    fetch_easy_cleanup(fetch_handle);
    fclose(headerfile);
    return -1;
  }

  /* we want the headers be written to this file handle */
  fetch_easy_setopt(fetch_handle, FETCHOPT_HEADERDATA, headerfile);

  /* we want the body be written to this file handle instead of stdout */
  fetch_easy_setopt(fetch_handle, FETCHOPT_WRITEDATA, bodyfile);

  /* get it! */
  fetch_easy_perform(fetch_handle);

  /* close the header file */
  fclose(headerfile);

  /* close the body file */
  fclose(bodyfile);

  /* cleanup fetch stuff */
  fetch_easy_cleanup(fetch_handle);

  return 0;
}
