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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "memdebug.h"

struct chunk_data {
  int remains;
  int print_content;
};

static
long chunk_bgn(const void *f, void *ptr, int remains)
{
  const struct curl_fileinfo *finfo = f;
  struct chunk_data *ch_d = ptr;
  ch_d->remains = remains;

  printf("=============================================================\n");
  printf("Remains:      %d\n", remains);
  printf("Filename:     %s\n", finfo->filename);
  if(finfo->strings.perm) {
    printf("Permissions:  %s", finfo->strings.perm);
    if(finfo->flags & CURLFINFOFLAG_KNOWN_PERM)
      printf(" (parsed => %o)", finfo->perm);
    printf("\n");
  }
  printf("Size:         %ldB\n", (long)finfo->size);
  if(finfo->strings.user)
    printf("User:         %s\n", finfo->strings.user);
  if(finfo->strings.group)
    printf("Group:        %s\n", finfo->strings.group);
  if(finfo->strings.time)
    printf("Time:         %s\n", finfo->strings.time);
  printf("Filetype:     ");
  switch(finfo->filetype) {
  case CURLFILETYPE_FILE:
    printf("regular file\n");
    break;
  case CURLFILETYPE_DIRECTORY:
    printf("directory\n");
    break;
  case CURLFILETYPE_SYMLINK:
    printf("symlink\n");
    printf("Target:       %s\n", finfo->strings.target);
    break;
  default:
    printf("other type\n");
    break;
  }
  if(finfo->filetype == CURLFILETYPE_FILE) {
    ch_d->print_content = 1;
    printf("Content:\n"
      "-------------------------------------------------------------\n");
  }
  if(strcmp(finfo->filename, "someothertext.txt") == 0) {
    printf("# THIS CONTENT WAS SKIPPED IN CHUNK_BGN CALLBACK #\n");
    return CURL_CHUNK_BGN_FUNC_SKIP;
  }
  return CURL_CHUNK_BGN_FUNC_OK;
}

static
long chunk_end(void *ptr)
{
  struct chunk_data *ch_d = ptr;
  if(ch_d->print_content) {
    ch_d->print_content = 0;
    printf("-------------------------------------------------------------\n");
  }
  if(ch_d->remains == 1)
    printf("=============================================================\n");
  return CURL_CHUNK_END_FUNC_OK;
}

CURLcode test(char *URL)
{
  CURL *handle = NULL;
  CURLcode res = CURLE_OK;
  struct chunk_data chunk_data = {0, 0};
  curl_global_init(CURL_GLOBAL_ALL);
  handle = curl_easy_init();
  if(!handle) {
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  test_setopt(handle, CURLOPT_URL, URL);
  test_setopt(handle, CURLOPT_WILDCARDMATCH, 1L);
  test_setopt(handle, CURLOPT_CHUNK_BGN_FUNCTION, chunk_bgn);
  test_setopt(handle, CURLOPT_CHUNK_END_FUNCTION, chunk_end);
  test_setopt(handle, CURLOPT_CHUNK_DATA, &chunk_data);

  res = curl_easy_perform(handle);

test_cleanup:
  if(handle)
    curl_easy_cleanup(handle);
  curl_global_cleanup();
  return res;
}
