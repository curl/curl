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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static int loadfile(const char *filename, void **filedata, size_t *filesize)
{
  size_t datasize = 0;
  void *data = NULL;
  if(filename) {
    FILE *fInCert = fopen(filename, "rb");

    if(fInCert) {
      long cert_tell = 0;
      bool continue_reading = fseek(fInCert, 0, SEEK_END) == 0;
      if(continue_reading)
        cert_tell = ftell(fInCert);
      if(cert_tell < 0)
        continue_reading = FALSE;
      else
        datasize = (size_t)cert_tell;
      if(continue_reading)
        continue_reading = fseek(fInCert, 0, SEEK_SET) == 0;
      if(continue_reading)
        data = malloc(datasize + 1);
      if((!data) ||
         ((int)fread(data, datasize, 1, fInCert) != 1))
        continue_reading = FALSE;
      fclose(fInCert);
      if(!continue_reading) {
        free(data);
        datasize = 0;
        data = NULL;
      }
   }
  }
  *filesize = datasize;
  *filedata = data;
  return data ? 1 : 0;
}

static FETCHcode test_cert_blob(const char *url, const char *cafile)
{
  FETCHcode code = FETCHE_OUT_OF_MEMORY;
  FETCH *fetch;
  struct fetch_blob blob;
  size_t certsize;
  void *certdata;

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    return FETCHE_FAILED_INIT;
  }

  if(loadfile(cafile, &certdata, &certsize)) {
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE,     1L);
    fetch_easy_setopt(fetch, FETCHOPT_HEADER,      1L);
    fetch_easy_setopt(fetch, FETCHOPT_URL,         url);
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT,   "FETCHOPT_CAINFO_BLOB");
    fetch_easy_setopt(fetch, FETCHOPT_SSL_OPTIONS,
                     FETCHSSLOPT_REVOKE_BEST_EFFORT);

    blob.data = certdata;
    blob.len = certsize;
    blob.flags = FETCH_BLOB_COPY;
    fetch_easy_setopt(fetch, FETCHOPT_CAINFO_BLOB, &blob);
    free(certdata);
    code = fetch_easy_perform(fetch);
  }
  fetch_easy_cleanup(fetch);

  return code;
}

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  fetch_global_init(FETCH_GLOBAL_DEFAULT);
  if(!strcmp("check", URL)) {
    FETCH *e;
    FETCHcode w = FETCHE_OK;
    struct fetch_blob blob = {0};
    e = fetch_easy_init();
    if(e) {
      w = fetch_easy_setopt(e, FETCHOPT_CAINFO_BLOB, &blob);
      if(w)
        printf("FETCHOPT_CAINFO_BLOB is not supported\n");
      fetch_easy_cleanup(e);
    }
    res = w;
  }
  else
    res = test_cert_blob(URL, libtest_arg2);

  fetch_global_cleanup();
  return res;
}
