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
/* <DESC>
 * A basic application source code using the multi interface doing two
 * transfers in parallel.
 * </DESC>
 */

#include <stdio.h>
#include <string.h>

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

  int still_running = 1; /* keep number of running handles */
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

  while (still_running)
  {
    FETCHMcode mc = fetch_multi_perform(multi_handle, &still_running);

    if (still_running)
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_poll(multi_handle, NULL, 0, 1000, NULL);

    if (mc)
      break;
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

  /* remove the transfers and cleanup the handles */
  for (i = 0; i < HANDLECOUNT; i++)
  {
    fetch_multi_remove_handle(multi_handle, handles[i]);
    fetch_easy_cleanup(handles[i]);
  }

  fetch_multi_cleanup(multi_handle);

  return 0;
}
