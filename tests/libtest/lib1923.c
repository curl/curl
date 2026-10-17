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
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h> /* RLIMIT_FSIZE */
#endif
#include <signal.h>  /* SIGXFSZ */

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT) &&       \
  defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
#define T1923_FSIZE_LIMIT 8192

/* Verify that a cookie jar save that fails partway through writing (the
   response carries enough big Set-Cookie headers that the jar content spans
   several stdio flushes, and RLIMIT_FSIZE is set to cut the write off in the
   middle of that, not on the very first byte) never gets renamed on top of
   the destination file, so the destination is not left containing
   partial/corrupted cookie data. */

static size_t t1923_discard(char *ptr, size_t size, size_t nmemb, void *ud)
{
  (void)ptr;
  (void)ud;
  return size * nmemb;
}

static CURLcode test_lib1923(const char *URL)
{
  CURLcode result;
  CURL *curl;
  struct rlimit rl_orig;
  struct rlimit rl;
  FILE *fp;
  long nread = -1;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result;

  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  easy_setopt(curl, CURLOPT_COOKIEFILE, "");
  easy_setopt(curl, CURLOPT_COOKIEJAR, libtest_arg2);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t1923_discard);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  if(getrlimit(RLIMIT_FSIZE, &rl_orig)) {
    curl_mfprintf(stderr, "getrlimit() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  signal(SIGXFSZ, SIG_IGN);
  rl = rl_orig;
  rl.rlim_cur = T1923_FSIZE_LIMIT;
  if(setrlimit(RLIMIT_FSIZE, &rl)) {
    curl_mfprintf(stderr, "setrlimit() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  curl_easy_cleanup(curl);
  curl = NULL;

  setrlimit(RLIMIT_FSIZE, &rl_orig);

  fp = curlx_fopen(libtest_arg2, FOPEN_READTEXT);
  if(fp) {
    if(!fseek(fp, 0, SEEK_END))
      nread = ftell(fp);
    curlx_fclose(fp);
  }

  if(nread) {
    curl_mfprintf(stderr, "FAIL: jar has %ld bytes, expected an empty "
                  "file since the write failure should have aborted the "
                  "save instead of installing a partial file\n", nread);
    result = TEST_ERR_FAILURE;
  }
  else
    curl_mprintf("cookie jar correctly left without partial data\n");
test_cleanup:
  if(curl)
    curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
#else
/* lacks the mechanisms to run this test */
static CURLcode test_lib1923(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif
