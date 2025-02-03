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

#define TEST_HANG_TIMEOUT 60 * 1000

static char const testData[] = ".abc\0xyz";
static fetch_off_t const testDataSize = sizeof(testData) - 1;

FETCHcode test(char *URL)
{
  FETCH *easy;
  FETCHM *multi_handle;
  int still_running; /* keep number of running handles */
  FETCHMsg *msg; /* for picking up messages with the transfer status */
  int msgs_left; /* how many messages are left */
  FETCHcode res = FETCHE_OK;

  start_test_timing();

  global_init(FETCH_GLOBAL_ALL);

  /* Allocate one fetch handle per transfer */
  easy = fetch_easy_init();

  /* init a multi stack */
  multi_handle = fetch_multi_init();

  /* add the individual transfer */
  fetch_multi_add_handle(multi_handle, easy);

  /* set the options (I left out a few, you'll get the point anyway) */
  fetch_easy_setopt(easy, FETCHOPT_URL, URL);
  fetch_easy_setopt(easy, FETCHOPT_POSTFIELDSIZE_LARGE, testDataSize);
  fetch_easy_setopt(easy, FETCHOPT_POSTFIELDS, testData);

  /* we start some action by calling perform right away */
  fetch_multi_perform(multi_handle, &still_running);

  abort_on_test_timeout();

  do {
    struct timeval timeout;
    int rc; /* select() return code */
    FETCHMcode mc; /* fetch_multi_fdset() return code */

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

    fetch_multi_timeout(multi_handle, &fetch_timeo);
    if(fetch_timeo >= 0) {
      fetchx_mstotv(&timeout, fetch_timeo);
      if(timeout.tv_sec > 1) {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
      }
    }

    /* get file descriptors from the transfers */
    mc = fetch_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_fdset() failed, code %d.\n", mc);
      break;
    }

    /* On success the value of maxfd is guaranteed to be >= -1. We call
       select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
       no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
       to sleep 100ms, which is the minimum suggested value in the
       fetch_multi_fdset() doc. */

    if(maxfd == -1) {
#if defined(_WIN32)
      Sleep(100);
      rc = 0;
#else
      /* Portable sleep for platforms other than Windows. */
      struct timeval wait = {0};
      wait.tv_usec = 100 * 1000; /* 100ms */
      rc = select(0, NULL, NULL, NULL, &wait);
#endif
    }
    else {
      /* Note that on some platforms 'timeout' may be modified by select().
         If you need access to the original value save a copy beforehand. */
      rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
    }

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0: /* timeout */
    default: /* action */
      fetch_multi_perform(multi_handle, &still_running);
      break;
    }

    abort_on_test_timeout();
  } while(still_running);

  /* See how the transfers went */
  do {
    msg = fetch_multi_info_read(multi_handle, &msgs_left);
    if(msg && msg->msg == FETCHMSG_DONE) {
      printf("HTTP transfer completed with status %d\n", msg->data.result);
      break;
    }

    abort_on_test_timeout();
  } while(msg);

test_cleanup:
  fetch_multi_cleanup(multi_handle);

  /* Free the fetch handles */
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();

  return res;
}
