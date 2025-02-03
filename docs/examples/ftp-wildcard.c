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
 * FTP wildcard pattern matching
 * </DESC>
 */
#include <fetch/fetch.h>
#include <stdio.h>

struct callback_data {
  FILE *output;
};

static long file_is_coming(struct fetch_fileinfo *finfo,
                           struct callback_data *data,
                           int remains);

static long file_is_downloaded(struct callback_data *data);

static size_t write_it(char *buff, size_t size, size_t nmemb,
                       void *cb_data);

int main(int argc, char **argv)
{
  /* fetch easy handle */
  FETCH *handle;

  /* help data */
  struct callback_data data = { 0 };

  /* global initialization */
  FETCHcode rc = fetch_global_init(FETCH_GLOBAL_ALL);
  if(rc)
    return (int)rc;

  /* initialization of easy handle */
  handle = fetch_easy_init();
  if(!handle) {
    fetch_global_cleanup();
    return FETCHE_OUT_OF_MEMORY;
  }

  /* turn on wildcard matching */
  fetch_easy_setopt(handle, FETCHOPT_WILDCARDMATCH, 1L);

  /* callback is called before download of concrete file started */
  fetch_easy_setopt(handle, FETCHOPT_CHUNK_BGN_FUNCTION, file_is_coming);

  /* callback is called after data from the file have been transferred */
  fetch_easy_setopt(handle, FETCHOPT_CHUNK_END_FUNCTION, file_is_downloaded);

  /* this callback writes contents into files */
  fetch_easy_setopt(handle, FETCHOPT_WRITEFUNCTION, write_it);

  /* put transfer data into callbacks */
  fetch_easy_setopt(handle, FETCHOPT_CHUNK_DATA, &data);
  fetch_easy_setopt(handle, FETCHOPT_WRITEDATA, &data);

  /* fetch_easy_setopt(handle, FETCHOPT_VERBOSE, 1L); */

  /* set a URL containing wildcard pattern (only in the last part) */
  if(argc == 2)
    fetch_easy_setopt(handle, FETCHOPT_URL, argv[1]);
  else
    fetch_easy_setopt(handle, FETCHOPT_URL, "ftp://example.com/test/*");

  /* and start transfer! */
  rc = fetch_easy_perform(handle);

  fetch_easy_cleanup(handle);
  fetch_global_cleanup();
  return (int)rc;
}

static long file_is_coming(struct fetch_fileinfo *finfo,
                           struct callback_data *data,
                           int remains)
{
  printf("%3d %40s %10luB ", remains, finfo->filename,
         (unsigned long)finfo->size);

  switch(finfo->filetype) {
  case FETCHFILETYPE_DIRECTORY:
    printf(" DIR\n");
    break;
  case FETCHFILETYPE_FILE:
    printf("FILE ");
    break;
  default:
    printf("OTHER\n");
    break;
  }

  if(finfo->filetype == FETCHFILETYPE_FILE) {
    /* do not transfer files >= 50B */
    if(finfo->size > 50) {
      printf("SKIPPED\n");
      return FETCH_CHUNK_BGN_FUNC_SKIP;
    }

    data->output = fopen(finfo->filename, "wb");
    if(!data->output) {
      return FETCH_CHUNK_BGN_FUNC_FAIL;
    }
  }

  return FETCH_CHUNK_BGN_FUNC_OK;
}

static long file_is_downloaded(struct callback_data *data)
{
  if(data->output) {
    printf("DOWNLOADED\n");
    fclose(data->output);
    data->output = 0x0;
  }
  return FETCH_CHUNK_END_FUNC_OK;
}

static size_t write_it(char *buff, size_t size, size_t nmemb,
                       void *cb_data)
{
  struct callback_data *data = cb_data;
  size_t written = 0;
  if(data->output)
    written = fwrite(buff, size, nmemb, data->output);
  else
    /* listing output */
    written = fwrite(buff, size, nmemb, stdout);
  return written;
}
