/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif
#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

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
  int rc = CURLE_OK;

  /* curl easy handle */
  CURL *handle;

  /* help data */
  struct callback_data data = { 0 };

  /* Call curl_global_init immediately after the program starts, while it is
  still only one thread and before it uses libcurl at all. If the function
  returns non-zero, something went wrong and you cannot use the other curl
  functions. */
  if(curl_global_init(CURL_GLOBAL_ALL)) {
    fprintf(stderr, "Fatal: The initialization of libcurl has failed.\n");
    return EXIT_FAILURE;
  }

  /* Call curl_global_cleanup immediately before the program exits, when the
  program is again only one thread and after its last use of libcurl. For
  example, you can use atexit to ensure the cleanup will be called at exit. */
  if(atexit(curl_global_cleanup)) {
    fprintf(stderr, "Fatal: atexit failed to register curl_global_cleanup.\n");
    curl_global_cleanup();
    return EXIT_FAILURE;
  }

  /* initialization of easy handle */
  handle = curl_easy_init();
  if(!handle) {
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

    data->output = fopen(finfo->filename, "w");
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
