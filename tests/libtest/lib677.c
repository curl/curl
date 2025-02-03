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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static const char testcmd[] = "A1 IDLE\r\n";
static char testbuf[1024];

FETCHcode test(char *URL)
{
  FETCHM *mfetch;
  FETCH *fetch = NULL;
  int mrun;
  fetch_socket_t sock = FETCH_SOCKET_BAD;
  time_t start = time(NULL);
  int state = 0;
  ssize_t pos = 0;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_DEFAULT);
  multi_init(mfetch);
  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 1L);
  if (fetch_multi_add_handle(mfetch, fetch))
    goto test_cleanup;

  while (time(NULL) - start < 5)
  {
    struct fetch_waitfd waitfd;

    multi_perform(mfetch, &mrun);
    for (;;)
    {
      int i;
      struct FETCHMsg *m = fetch_multi_info_read(mfetch, &i);

      if (!m)
        break;
      if (m->msg == FETCHMSG_DONE && m->easy_handle == fetch)
      {
        fetch_easy_getinfo(fetch, FETCHINFO_ACTIVESOCKET, &sock);
        if (sock == FETCH_SOCKET_BAD)
          goto test_cleanup;
        printf("Connected fine, extracted socket. Moving on\n");
      }
    }

    if (sock != FETCH_SOCKET_BAD)
    {
      waitfd.events = state ? FETCH_WAIT_POLLIN : FETCH_WAIT_POLLOUT;
      waitfd.revents = 0;
      fetch_easy_getinfo(fetch, FETCHINFO_ACTIVESOCKET, &sock);
      waitfd.fd = sock;
    }
    fetch_multi_wait(mfetch, &waitfd, sock == FETCH_SOCKET_BAD ? 0 : 1, 50,
                     &mrun);
    if ((sock != FETCH_SOCKET_BAD) && (waitfd.revents & waitfd.events))
    {
      size_t len = 0;

      if (!state)
      {
        FETCHcode ec;
        ec = fetch_easy_send(fetch, testcmd + pos,
                             sizeof(testcmd) - 1 - pos, &len);
        if (ec == FETCHE_AGAIN)
        {
          continue;
        }
        else if (ec)
        {
          fprintf(stderr, "fetch_easy_send() failed, with code %d (%s)\n",
                  (int)ec, fetch_easy_strerror(ec));
          res = ec;
          goto test_cleanup;
        }
        if (len > 0)
          pos += len;
        else
          pos = 0;
        if (pos == sizeof(testcmd) - 1)
        {
          state++;
          pos = 0;
        }
      }
      else if (pos < (ssize_t)sizeof(testbuf))
      {
        FETCHcode ec;
        ec = fetch_easy_recv(fetch, testbuf + pos, sizeof(testbuf) - pos, &len);
        if (ec == FETCHE_AGAIN)
        {
          continue;
        }
        else if (ec)
        {
          fprintf(stderr, "fetch_easy_recv() failed, with code %d (%s)\n",
                  (int)ec, fetch_easy_strerror(ec));
          res = ec;
          goto test_cleanup;
        }
        if (len > 0)
          pos += len;
      }
      if (len <= 0)
        sock = FETCH_SOCKET_BAD;
    }
  }

  if (state)
  {
    fwrite(testbuf, pos, 1, stdout);
    putchar('\n');
  }

  fetch_multi_remove_handle(mfetch, fetch);
test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_multi_cleanup(mfetch);

  fetch_global_cleanup();
  return res;
}
