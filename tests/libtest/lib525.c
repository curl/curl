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

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  FILE *hd_src = NULL;
  int hd;
  struct_stat file_info;
  CURLM *m = NULL;
  int running;

  start_test_timing();

  if(!libtest_arg2) {
#ifdef LIB529
    /* test 529 */
    fprintf(stderr, "Usage: lib529 [url] [uploadfile]\n");
#else
    /* test 525 */
    fprintf(stderr, "Usage: lib525 [url] [uploadfile]\n");
#endif
    return TEST_ERR_USAGE;
  }

  hd_src = fopen(libtest_arg2, "rb");
  if(!hd_src) {
    fprintf(stderr, "fopen failed with error (%d) %s\n",
            errno, strerror(errno));
    fprintf(stderr, "Error opening file '%s'\n", libtest_arg2);
    return TEST_ERR_FOPEN;
  }

  /* get the file size of the local file */
#ifdef UNDER_CE
  hd = stat(libtest_arg2, &file_info);
#else
  hd = fstat(fileno(hd_src), &file_info);
#endif
  if(hd == -1) {
    /* can't open file, bail out */
    fprintf(stderr, "fstat() failed with error (%d) %s\n",
            errno, strerror(errno));
    fprintf(stderr, "Error opening file '%s'\n", libtest_arg2);
    fclose(hd_src);
    return TEST_ERR_FSTAT;
  }

  res_global_init(CURL_GLOBAL_ALL);
  if(res) {
    fclose(hd_src);
    return res;
  }

  easy_init(curl);

  /* enable uploading */
  easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  /* specify target */
  easy_setopt(curl, CURLOPT_URL, URL);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* use active FTP */
  easy_setopt(curl, CURLOPT_FTPPORT, "-");

  /* now specify which file to upload */
  easy_setopt(curl, CURLOPT_READDATA, hd_src);

  /* NOTE: if you want this code to work on Windows with libcurl as a DLL, you
     MUST also provide a read callback with CURLOPT_READFUNCTION. Failing to
     do so will give you a crash since a DLL may not use the variable's memory
     when passed in to it from an app like this. */

  /* Set the size of the file to upload (optional).  If you give a *_LARGE
     option you MUST make sure that the type of the passed-in argument is a
     curl_off_t. If you use CURLOPT_INFILESIZE (without _LARGE) you must
     make sure that to pass in a type 'long' argument. */
  easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

  multi_init(m);

  multi_add_handle(m, curl);

  for(;;) {
    struct timeval interval;
    fd_set rd, wr, exc;
    int maxfd = -99;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    multi_perform(m, &running);

    abort_on_test_timeout();

    if(!running)
      break; /* done */

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);

    multi_fdset(m, &rd, &wr, &exc, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &rd, &wr, &exc, &interval);

    abort_on_test_timeout();
  }

test_cleanup:

#ifdef LIB529
  /* test 529 */
  /* proper cleanup sequence - type PA */
  curl_multi_remove_handle(m, curl);
  curl_multi_cleanup(m);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
#else
  /* test 525 */
  /* proper cleanup sequence - type PB */
  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
  curl_global_cleanup();
#endif

  /* close the local file */
  fclose(hd_src);

  return res;
}
