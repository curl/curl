/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
/* <DESC>
 * FTP wildcard pattern matching
 * </DESC>
 */
#include <curl/curl.h>
#include <stdio.h>

struct callback_data {
  FILE *output;
};

static long file_is_coming(struct curl_fileinfo *finfo,
                           struct callback_data *data,
                           int remains);

static long file_is_downloaded(struct callback_data *data);

static size_t write_it(char *buff, size_t size, size_t nmemb,
                       void *cb_data);

int main(int argc, char **argv)
{
  /* curl easy handle */
  CURL *handle;

  /* help data */
  struct callback_data data = { 0 };

  /* global initialization */
  int rc = curl_global_init(CURL_GLOBAL_ALL);
  if(rc)
    return rc;

  /* initialization of easy handle */
  handle = curl_easy_init();
  if(!handle) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }

  /* turn on wildcard matching */
  curl_easy_setopt(handle, CURLOPT_WILDCARDMATCH, 1L);

  /* callback is called before download of concrete file started */
  curl_easy_setopt(handle, CURLOPT_CHUNK_BGN_FUNCTION, file_is_coming);

  /* callback is called after data from the file have been transferred */
  curl_easy_setopt(handle, CURLOPT_CHUNK_END_FUNCTION, file_is_downloaded);

  /* this callback will write contents into files */
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_it);

  /* put transfer data into callbacks */
  curl_easy_setopt(handle, CURLOPT_CHUNK_DATA, &data);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &data);

  /* curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L); */

  /* set an URL containing wildcard pattern (only in the last part) */
  if(argc == 2)
    curl_easy_setopt(handle, CURLOPT_URL, argv[1]);
  else
    curl_easy_setopt(handle, CURLOPT_URL, "ftp://example.com/test/*");

  /* and start transfer! */
  rc = curl_easy_perform(handle);

  curl_easy_cleanup(handle);
  curl_global_cleanup();
  return rc;
}

static long file_is_coming(struct curl_fileinfo *finfo,
                           struct callback_data *data,
                           int remains)
{
  printf("%3d %40s %10luB ", remains, finfo->filename,
         (unsigned long)finfo->size);

  switch(finfo->filetype) {
  case CURLFILETYPE_DIRECTORY:
    printf(" DIR\n");
    break;
  case CURLFILETYPE_FILE:
    printf("FILE ");
    break;
  default:
    printf("OTHER\n");
    break;
  }

  if(finfo->filetype == CURLFILETYPE_FILE) {
    /* do not transfer files >= 50B */
    if(finfo->size > 50) {
      printf("SKIPPED\n");
      return CURL_CHUNK_BGN_FUNC_SKIP;
    }

    data->output = fopen(finfo->filename, "wb");
    if(!data->output) {
      return CURL_CHUNK_BGN_FUNC_FAIL;
    }
  }

  return CURL_CHUNK_BGN_FUNC_OK;
}

static long file_is_downloaded(struct callback_data *data)
{
  if(data->output) {
    printf("DOWNLOADED\n");
    fclose(data->output);
    data->output = 0x0;
  }
  return CURL_CHUNK_END_FUNC_OK;
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
