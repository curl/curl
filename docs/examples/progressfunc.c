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
 * Use the progress callbacks, old and/or new one depending on available
 * libfetch version.
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL 3000000
#define STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES 6000

struct myprogress
{
  fetch_off_t lastruntime; /* type depends on version, see above */
  FETCH *fetch;
};

/* this is how the FETCHOPT_XFERINFOFUNCTION callback works */
static int xferinfo(void *p,
                    fetch_off_t dltotal, fetch_off_t dlnow,
                    fetch_off_t ultotal, fetch_off_t ulnow)
{
  struct myprogress *myp = (struct myprogress *)p;
  FETCH *fetch = myp->fetch;
  fetch_off_t curtime = 0;

  fetch_easy_getinfo(fetch, FETCHINFO_TOTAL_TIME_T, &curtime);

  /* under certain circumstances it may be desirable for certain functionality
     to only run every N seconds, in order to do this the transaction time can
     be used */
  if ((curtime - myp->lastruntime) >= MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL)
  {
    myp->lastruntime = curtime;
    fprintf(stderr, "TOTAL TIME: %lu.%06lu\r\n",
            (unsigned long)(curtime / 1000000),
            (unsigned long)(curtime % 1000000));
  }

  fprintf(stderr, "UP: %lu of %lu  DOWN: %lu of %lu\r\n",
          (unsigned long)ulnow, (unsigned long)ultotal,
          (unsigned long)dlnow, (unsigned long)dltotal);

  if (dlnow > STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES)
    return 1;
  return 0;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  struct myprogress prog;

  fetch = fetch_easy_init();
  if (fetch)
  {
    prog.lastruntime = 0;
    prog.fetch = fetch;

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");

    fetch_easy_setopt(fetch, FETCHOPT_XFERINFOFUNCTION, xferinfo);
    /* pass the struct pointer into the xferinfo function */
    fetch_easy_setopt(fetch, FETCHOPT_XFERINFODATA, &prog);

    fetch_easy_setopt(fetch, FETCHOPT_NOPROGRESS, 0L);
    res = fetch_easy_perform(fetch);

    if (res != FETCHE_OK)
      fprintf(stderr, "%s\n", fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return (int)res;
}
