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

#include "memdebug.h"

static size_t t1507_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  return CURL_READFUNC_ABORT;
}

static CURLcode test_lib1507(const char *URL)
{
  static const int MULTI_PERFORM_HANG_TIMEOUT = 60 * 1000;

  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  CURLM *mcurl = NULL;
  int still_running = 1;
  struct curltime mp_start;
  struct curl_slist *rcpt_list = NULL;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  easy_init(curl);

  multi_init(mcurl);

  rcpt_list = curl_slist_append(rcpt_list, "<1507-recipient@example.com>");
#if 0
  /* more addresses can be added here */
  rcpt_list = curl_slist_append(rcpt_list, "<others@example.com>");
#endif
  curl_easy_setopt(curl, CURLOPT_URL, URL);
#if 0
  curl_easy_setopt(curl, CURLOPT_USERNAME, "user@example.com");
  curl_easy_setopt(curl, CURLOPT_PASSWORD, "123qwerty");
#endif
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, t1507_read_cb);
  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "<1507-realuser@example.com>");
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, rcpt_list);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  multi_add_handle(mcurl, curl);

  mp_start = curlx_now();

  /* we start some action by calling perform right away */
  curl_multi_perform(mcurl, &still_running);

  while(still_running) {
    struct timeval timeout;
    int rc; /* select() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    curl_multi_timeout(mcurl, &curl_timeo);
    if(curl_timeo >= 0) {
      curlx_mstotv(&timeout, curl_timeo);
      if(timeout.tv_sec > 1) {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
      }
    }

    /* get file descriptors from the transfers */
    curl_multi_fdset(mcurl, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* In a real-world program you OF COURSE check the return code of the
       function calls.  On success, the value of maxfd is guaranteed to be
       greater or equal than -1.  We call select(maxfd + 1, ...), specially in
       case of (maxfd == -1), we call select(0, ...), which is basically equal
       to sleep. */

    rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    if(curlx_timediff(curlx_now(), mp_start) > MULTI_PERFORM_HANG_TIMEOUT) {
      curl_mfprintf(stderr, "ABORTING TEST, since it seems "
                    "that it would have run forever.\n");
      break;
    }

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0: /* timeout */
    default: /* action */
      curl_multi_perform(mcurl, &still_running);
      break;
    }
  }

test_cleanup:

  curl_slist_free_all(rcpt_list);
  curl_multi_remove_handle(mcurl, curl);
  curl_multi_cleanup(mcurl);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
