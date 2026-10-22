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

/* CURLOPT_SSLCERT_BLOB / CURLOPT_SSLKEY_BLOB -- in-memory client auth */

#include "first.h"

static int t2095_loadfile(const char *filename,
                          void **filedata,
                          size_t *filesize)
{
  size_t datasize = 0;
  void *data = NULL;
  if(filename) {
    FILE *fIn = curlx_fopen(filename, "rb");

    if(fIn) {
      long tell = 0;
      bool ok = fseek(fIn, 0, SEEK_END) == 0;
      if(ok)
        tell = ftell(fIn);
      if(tell < 0)
        ok = FALSE;
      else
        datasize = (size_t)tell;
      if(ok)
        ok = fseek(fIn, 0, SEEK_SET) == 0;
      if(ok)
        data = curlx_malloc(datasize + 1);
      if(!data || ((int)fread(data, datasize, 1, fIn) != 1))
        ok = FALSE;
      curlx_fclose(fIn);
      if(!ok) {
        curlx_safefree(data);
        datasize = 0;
      }
    }
  }
  *filesize = datasize;
  *filedata = data;
  return data ? 1 : 0;
}

static CURLcode t2095_cert_blob(const char *url,
                                const char *cafile,
                                const char *certfile,
                                const char *keyfile)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  CURL *curl;
  struct curl_blob blob;
  size_t sz;
  void *data;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    return CURLE_FAILED_INIT;
  }

  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "CURLOPT_SSLCERT_BLOB");

  if(t2095_loadfile(cafile, &data, &sz)) {
    blob.data = data;
    blob.len = sz;
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
    curlx_free(data);
  }

  result = CURLE_OUT_OF_MEMORY;
  if(t2095_loadfile(certfile, &data, &sz)) {
    blob.data = data;
    blob.len = sz;
    blob.flags = CURL_BLOB_COPY;
    result = curl_easy_setopt(curl, CURLOPT_SSLCERT_BLOB, &blob);
    curlx_free(data);
  }
  if(result)
    goto cleanup;

  if(t2095_loadfile(keyfile, &data, &sz)) {
    blob.data = data;
    blob.len = sz;
    blob.flags = CURL_BLOB_COPY;
    result = curl_easy_setopt(curl, CURLOPT_SSLKEY_BLOB, &blob);
    curlx_free(data);
  }
  if(result)
    goto cleanup;

  result = curl_easy_perform(curl);

cleanup:
  curl_easy_cleanup(curl);
  return result;
}

static CURLcode test_lib2095(const char *URL)
{
  CURLcode result = CURLE_OK;
  curl_global_init(CURL_GLOBAL_ALL);
  if(!strcmp("check", URL)) {
    CURLcode w = CURLE_OK;
    struct curl_blob blob = { CURL_UNCONST("x"), 1, 0 };
    CURL *curl = curl_easy_init();
    if(curl) {
      w = curl_easy_setopt(curl, CURLOPT_SSLCERT_BLOB, &blob);
      if(w)
        curl_mprintf("CURLOPT_SSLCERT_BLOB is not supported\n");
      else {
        w = curl_easy_setopt(curl, CURLOPT_SSLKEY_BLOB, &blob);
        if(w)
          curl_mprintf("CURLOPT_SSLKEY_BLOB is not supported\n");
      }
      curl_easy_cleanup(curl);
    }
    result = w;
  }
  else
    result = t2095_cert_blob(URL, libtest_arg2, libtest_arg3, libtest_arg4);
  curl_global_cleanup();
  return result;
}
