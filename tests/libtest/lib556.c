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

#include "warnless.h"
#include "memdebug.h"

/* For Windows, mainly (may be moved in a config file?) */
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
#ifdef LIB696
  int transfers = 0;
#endif

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_CONNECT_ONLY, 1L);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

#ifdef LIB696
again:
#endif

  res = fetch_easy_perform(fetch);

  if (!res)
  {
    /* we are connected, now get an HTTP document the raw way */
    const char *request =
        "GET /556 HTTP/1.1\r\n"
        "Host: ninja\r\n\r\n";
    const char *sbuf = request;
    size_t sblen = strlen(request);
    size_t nwritten = 0, nread = 0;

    do
    {
      char buf[1024];

      if (sblen)
      {
        res = fetch_easy_send(fetch, sbuf, sblen, &nwritten);
        if (res && res != FETCHE_AGAIN)
          break;
        if (nwritten > 0)
        {
          sbuf += nwritten;
          sblen -= nwritten;
        }
      }

      /* busy-read like crazy */
      res = fetch_easy_recv(fetch, buf, sizeof(buf), &nread);

      if (nread)
      {
        /* send received stuff to stdout */
        if ((size_t)write(STDOUT_FILENO, buf, nread) != nread)
        {
          fprintf(stderr, "write() failed: errno %d (%s)\n",
                  errno, strerror(errno));
          res = TEST_ERR_FAILURE;
          break;
        }
      }

    } while ((res == FETCHE_OK && nread) || (res == FETCHE_AGAIN));

    if (res && res != FETCHE_AGAIN)
      res = TEST_ERR_FAILURE;
  }

#ifdef LIB696
  ++transfers;
  /* perform the transfer a second time */
  if (!res && transfers == 1)
    goto again;
#endif

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
