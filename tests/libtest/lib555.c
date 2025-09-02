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

/* This test case is supposed to be identical to 547 except that this uses the
 * multi interface and 547 is easy interface.
 *
 * argv1 = URL
 * argv2 = proxy
 * argv3 = proxyuser:password
 */

#include "first.h"

#include "memdebug.h"

static const char t555_uploadthis[] = "this is the blurb we want to upload\n";
#define T555_DATALEN (sizeof(t555_uploadthis)-1)

static size_t t555_read_cb(char *ptr, size_t size, size_t nmemb, void *clientp)
{
  int *counter = (int *)clientp;

  if(*counter) {
    /* only do this once and then require a clearing of this */
    curl_mfprintf(stderr, "READ ALREADY DONE!\n");
    return 0;
  }
  (*counter)++; /* bump */

  if(size * nmemb >= T555_DATALEN) {
    curl_mfprintf(stderr, "READ!\n");
    strcpy(ptr, t555_uploadthis);
    return T555_DATALEN;
  }
  curl_mfprintf(stderr, "READ NOT FINE!\n");
  return 0;
}

static curlioerr t555_ioctl_callback(CURL *handle, int cmd, void *clientp)
{
  int *counter = (int *)clientp;
  (void)handle;
  if(cmd == CURLIOCMD_RESTARTREAD) {
    curl_mfprintf(stderr, "REWIND!\n");
    *counter = 0; /* clear counter to make the read callback restart */
  }
  return CURLIOE_OK;
}

static CURLcode test_lib555(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  int counter = 0;
  CURLM *m = NULL;
  int running = 1;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_HEADER, 1L);

  /* read the POST data from a callback */
  easy_setopt(curl, CURLOPT_IOCTLFUNCTION, t555_ioctl_callback);
  easy_setopt(curl, CURLOPT_IOCTLDATA, &counter);

  easy_setopt(curl, CURLOPT_READFUNCTION, t555_read_cb);
  easy_setopt(curl, CURLOPT_READDATA, &counter);
  /* We CANNOT do the POST fine without setting the size (or choose
     chunked)! */
  easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)T555_DATALEN);

  easy_setopt(curl, CURLOPT_POST, 1L);
  easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);
  easy_setopt(curl, CURLOPT_PROXYUSERPWD, libtest_arg3);
  easy_setopt(curl, CURLOPT_PROXYAUTH,
              CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM);

  multi_init(m);

  multi_add_handle(m, curl);

  while(running) {
    struct timeval timeout;
    fd_set fdread, fdwrite, fdexcep;
    int maxfd = -99;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100000L; /* 100 ms */

    multi_perform(m, &running);

    abort_on_test_timeout();

    if(!running)
      break; /* done */

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    multi_fdset(m, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    abort_on_test_timeout();
  }

test_cleanup:

  /* proper cleanup sequence - type PA */

  curl_multi_remove_handle(m, curl);
  curl_multi_cleanup(m);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
