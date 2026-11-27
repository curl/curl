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
#include "first.h"

static size_t t1558_truncate(char *ptr, size_t size, size_t nmemb, void *userp)
{
  FILE *file = curlx_fopen(userp, FOPEN_WRITETEXT);
  (void)ptr;
  if(!file)
    return CURL_WRITEFUNC_ERROR;
  return curlx_fclose(file) ? CURL_WRITEFUNC_ERROR : size * nmemb;
}

static size_t t1558_slow_write(char *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  int *calls = userp;
  (void)ptr;
  if((*calls)++)
    return CURL_WRITEFUNC_ERROR;
  curlx_wait_ms(200);
  return size * nmemb;
}

static CURLcode test_lib1558(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  long protocol = 0;
  FILE *file;
  size_t i;
  int calls = 0;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr, "curl_easy_perform() returned %d (%s)\n",
                  (int)result, curl_easy_strerror(result));
    goto test_cleanup;
  }

  result = curl_easy_getinfo(curl, CURLINFO_PROTOCOL, &protocol);
  if(result) {
    curl_mfprintf(stderr, "curl_easy_getinfo() returned %d (%s)\n",
                  (int)result, curl_easy_strerror(result));
    goto test_cleanup;
  }

  curl_mprintf("Protocol: %lx\n", (unsigned long)protocol);

  /* The file transfer loop must enforce the overall timeout too. */
  file = curlx_fopen(libtest_arg2, FOPEN_APPENDTEXT);
  if(!file) {
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  for(i = 0; i < 32768; i++)
    fputc('x', file);
  curlx_fclose(file);
  easy_setopt(curl, CURLOPT_BUFFERSIZE, 1024L);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t1558_slow_write);
  easy_setopt(curl, CURLOPT_WRITEDATA, &calls);
  easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
  result = curl_easy_perform(curl);
  if(result != CURLE_OPERATION_TIMEDOUT) {
    curl_mfprintf(stderr, "file timeout returned %d, expected TIMEDOUT\n",
                  (int)result);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  easy_setopt(curl, CURLOPT_TIMEOUT_MS, 0L);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
  easy_setopt(curl, CURLOPT_WRITEDATA, stdout);

  /* Shrink the source after its size was determined, before reading it. */
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, t1558_truncate);
  easy_setopt(curl, CURLOPT_HEADERDATA, libtest_arg2);
  result = curl_easy_perform(curl);
  if(result != CURLE_PARTIAL_FILE) {
    curl_mfprintf(stderr, "premature EOF returned %d, expected PARTIAL_FILE\n",
                  (int)result);
    result = TEST_ERR_FAILURE;
  }
  else
    result = CURLE_OK;

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result; /* return the final return code */
}
