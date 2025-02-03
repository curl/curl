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
 * WebSocket download-only using write callback
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

static size_t writecb(char *b, size_t size, size_t nitems, void *p)
{
  FETCH *easy = p;
  size_t i;
  const struct fetch_ws_frame *frame = fetch_ws_meta(easy);
  fprintf(stderr, "Type: %s\n", frame->flags & FETCHWS_BINARY ? "binary" : "text");
  fprintf(stderr, "Bytes: %u", (unsigned int)(nitems * size));
  for (i = 0; i < nitems; i++)
    fprintf(stderr, "%02x ", (unsigned char)b[i]);
  return nitems;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "wss://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, writecb);
    /* pass the easy handle to the callback */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, fetch);

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
