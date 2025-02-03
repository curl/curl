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
 * Upload to a file:// URL
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
#undef stat
#define stat _stat
#undef fstat
#define fstat _fstat
#define fileno _fileno
#endif

int main(void)
{
  FETCH *fetch;
  FETCHcode res;
  struct stat file_info;
  fetch_off_t speed_upload, total_time;
  FILE *fd;

  fd = fopen("debugit", "rb"); /* open file to upload */
  if(!fd)
    return 1; /* cannot continue */

  /* to get the file size */
  if(fstat(fileno(fd), &file_info) != 0) {
    fclose(fd);
    return 1; /* cannot continue */
  }

  fetch = fetch_easy_init();
  if(fetch) {
    /* upload to this place */
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "file:///home/dast/src/fetch/debug/new");

    /* tell it to "upload" to the URL */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* set where to read from (on Windows you need to use READFUNCTION too) */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, fd);

    /* and give the size of the upload (optional) */
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE_LARGE,
                     (fetch_off_t)file_info.st_size);

    /* enable verbose for easier tracing */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if(res != FETCHE_OK) {
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));
    }
    else {
      /* now extract transfer info */
      fetch_easy_getinfo(fetch, FETCHINFO_SPEED_UPLOAD_T, &speed_upload);
      fetch_easy_getinfo(fetch, FETCHINFO_TOTAL_TIME_T, &total_time);

      fprintf(stderr, "Speed: %lu bytes/sec during %lu.%06lu seconds\n",
              (unsigned long)speed_upload,
              (unsigned long)(total_time / 1000000),
              (unsigned long)(total_time % 1000000));
    }
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fclose(fd);
  return 0;
}
