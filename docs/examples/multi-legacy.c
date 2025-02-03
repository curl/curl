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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * A basic application source code using the multi interface doing two
 * transfers in parallel without fetch_multi_wait/poll.
 * </DESC>
 */

#include <stdio.h>
#include <string.h>

/* somewhat Unix-specific */
#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#endif

/* fetch stuff */
#include <fetch/fetch.h>

/*
 * Download an HTTP file and upload an FTP file simultaneously.
 */

#define HANDLECOUNT 2 /* Number of simultaneous transfers */
#define HTTP_HANDLE 0 /* Index for the HTTP transfer */
#define FTP_HANDLE 1  /* Index for the FTP transfer */

int main(void)
{
  FETCH *handles[HANDLECOUNT];
  FETCHM *multi_handle;

  int still_running = 0; /* keep number of running handles */
  int i;

  FETCHMsg *msg; /* for picking up messages with the transfer status */
  int msgs_left; /* how many messages are left */

  /* Allocate one fetch handle per transfer */
  for (i = 0; i < HANDLECOUNT; i++)
    handles[i] = fetch_easy_init();

  /* set the options (I left out a few, you get the point anyway) */
  fetch_easy_setopt(handles[HTTP_HANDLE], FETCHOPT_URL, "https://example.com");

  fetch_easy_setopt(handles[FTP_HANDLE], FETCHOPT_URL, "ftp://example.com");
  fetch_easy_setopt(handles[FTP_HANDLE], FETCHOPT_UPLOAD, 1L);

  /* init a multi stack */
  multi_handle = fetch_multi_init();

  /* add the individual transfers */
  for (i = 0; i < HANDLECOUNT; i++)
    fetch_multi_add_handle(multi_handle, handles[i]);

  /* we start some action by calling perform right away */
  fetch_multi_perform(multi_handle, &still_running);

  while (still_running)
  {
    struct timeval timeout;
    int rc;        /* select() return code */
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
    if (fetch_timeo >= 0)
    {
#if defined(MSDOS) || defined(__AMIGA__)
      timeout.tv_sec = (time_t)(fetch_timeo / 1000);
#else
      timeout.tv_sec = fetch_timeo / 1000;
#endif
      if (timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
#if defined(MSDOS) || defined(__AMIGA__)
        timeout.tv_usec = (time_t)(fetch_timeo % 1000) * 1000;
#else
        timeout.tv_usec = (int)(fetch_timeo % 1000) * 1000;
#endif
    }

    /* get file descriptors from the transfers */
    mc = fetch_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    if (mc != FETCHM_OK)
    {
      fprintf(stderr, "fetch_multi_fdset() failed, code %d.\n", mc);
      break;
    }

    /* On success the value of maxfd is guaranteed to be >= -1. We call
       select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
       no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
       to sleep 100ms, which is the minimum suggested value in the
       fetch_multi_fdset() doc. */

    if (maxfd == -1)
    {
#ifdef _WIN32
      Sleep(100);
      rc = 0;
#else
      /* Portable sleep for platforms other than Windows. */
      struct timeval wait = {0};
      wait.tv_usec = 100 * 1000; /* 100ms */
      rc = select(0, NULL, NULL, NULL, &wait);
#endif
    }
    else
    {
      /* Note that on some platforms 'timeout' may be modified by select().
         If you need access to the original value save a copy beforehand. */
      rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
    }

    switch (rc)
    {
    case -1:
      /* select error */
      break;
    case 0:  /* timeout */
    default: /* action */
      fetch_multi_perform(multi_handle, &still_running);
      break;
    }
  }

  /* See how the transfers went */
  /* !checksrc! disable EQUALSNULL 1 */
  while ((msg = fetch_multi_info_read(multi_handle, &msgs_left)) != NULL)
  {
    if (msg->msg == FETCHMSG_DONE)
    {
      int idx;

      /* Find out which handle this message is about */
      for (idx = 0; idx < HANDLECOUNT; idx++)
      {
        int found = (msg->easy_handle == handles[idx]);
        if (found)
          break;
      }

      switch (idx)
      {
      case HTTP_HANDLE:
        printf("HTTP transfer completed with status %d\n", msg->data.result);
        break;
      case FTP_HANDLE:
        printf("FTP transfer completed with status %d\n", msg->data.result);
        break;
      }
    }
  }

  fetch_multi_cleanup(multi_handle);

  /* Free the fetch handles */
  for (i = 0; i < HANDLECOUNT; i++)
    fetch_easy_cleanup(handles[i]);

  return 0;
}
