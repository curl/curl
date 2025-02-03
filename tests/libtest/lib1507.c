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
#include "timediff.h"
#include "warnless.h"
#include "memdebug.h"

/*
 * This is the list of basic details you need to tweak to get things right.
 */
#define USERNAME "user@example.com"
#define PASSWORD "123qwerty"
#define RECIPIENT "<1507-recipient@example.com>"
#define MAILFROM "<1507-realuser@example.com>"

#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  return FETCH_READFUNC_ABORT;
}

FETCHcode test(char *URL)
{
   FETCHcode res = FETCHE_OK;
   FETCH *fetch = NULL;
   FETCHM *mfetch = NULL;
   int still_running = 1;
   struct timeval mp_start;
   struct fetch_slist *rcpt_list = NULL;

   fetch_global_init(FETCH_GLOBAL_DEFAULT);

   easy_init(fetch);

   multi_init(mfetch);

   rcpt_list = fetch_slist_append(rcpt_list, RECIPIENT);
   /* more addresses can be added here
      rcpt_list = fetch_slist_append(rcpt_list, "<others@example.com>");
   */

   fetch_easy_setopt(fetch, FETCHOPT_URL, URL);
#if 0
   fetch_easy_setopt(fetch, FETCHOPT_USERNAME, USERNAME);
   fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, PASSWORD);
#endif
   fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);
   fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);
   fetch_easy_setopt(fetch, FETCHOPT_MAIL_FROM, MAILFROM);
   fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT, rcpt_list);
   fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
   multi_add_handle(mfetch, fetch);

   mp_start = tutil_tvnow();

  /* we start some action by calling perform right away */
  fetch_multi_perform(mfetch, &still_running);

  while(still_running) {
    struct timeval timeout;
    int rc; /* select() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long fetch_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    fetch_multi_timeout(mfetch, &fetch_timeo);
    if(fetch_timeo >= 0) {
      fetchx_mstotv(&timeout, fetch_timeo);
      if(timeout.tv_sec > 1) {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
      }
    }

    /* get file descriptors from the transfers */
    fetch_multi_fdset(mfetch, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* In a real-world program you OF COURSE check the return code of the
       function calls.  On success, the value of maxfd is guaranteed to be
       greater or equal than -1.  We call select(maxfd + 1, ...), specially in
       case of (maxfd == -1), we call select(0, ...), which is basically equal
       to sleep. */

    rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    if(tutil_tvdiff(tutil_tvnow(), mp_start) > MULTI_PERFORM_HANG_TIMEOUT) {
      fprintf(stderr, "ABORTING TEST, since it seems "
              "that it would have run forever.\n");
      break;
    }

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0: /* timeout */
    default: /* action */
      fetch_multi_perform(mfetch, &still_running);
      break;
    }
  }

test_cleanup:

  fetch_slist_free_all(rcpt_list);
  fetch_multi_remove_handle(mfetch, fetch);
  fetch_multi_cleanup(mfetch);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
