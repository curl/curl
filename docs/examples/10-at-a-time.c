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
 * Download many files in parallel, in the same thread.
 * </DESC>
 */

#include <stdlib.h>
#include <string.h>
#include <fetch/fetch.h>

static const char *urls[] = {
    "https://www.microsoft.com",
    "https://opensource.org",
    "https://www.google.com",
    "https://www.yahoo.com",
    "https://www.ibm.com",
    "https://www.mysql.com",
    "https://www.oracle.com",
    "https://www.ripe.net",
    "https://www.iana.org",
    "https://www.amazon.com",
    "https://www.netcraft.com",
    "https://www.heise.de",
    "https://www.chip.de",
    "https://www.ca.com",
    "https://www.cnet.com",
    "https://www.mozilla.org",
    "https://www.cnn.com",
    "https://www.wikipedia.org",
    "https://www.dell.com",
    "https://www.hp.com",
    "https://www.cert.org",
    "https://www.mit.edu",
    "https://www.nist.gov",
    "https://www.ebay.com",
    "https://www.playstation.com",
    "https://www.uefa.com",
    "https://www.ieee.org",
    "https://www.apple.com",
    "https://www.symantec.com",
    "https://www.zdnet.com",
    "https://www.fujitsu.com/global/",
    "https://www.supermicro.com",
    "https://www.hotmail.com",
    "https://www.ietf.org",
    "https://www.bbc.co.uk",
    "https://news.google.com",
    "https://www.foxnews.com",
    "https://www.msn.com",
    "https://www.wired.com",
    "https://www.sky.com",
    "https://www.usatoday.com",
    "https://www.cbs.com",
    "https://www.nbc.com/",
    "https://slashdot.org",
    "https://www.informationweek.com",
    "https://apache.org",
    "https://www.un.org",
};

#define MAX_PARALLEL 10 /* number of simultaneous transfers */
#define NUM_URLS sizeof(urls) / sizeof(char *)

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n * l;
}

static void add_transfer(FETCHM *cm, unsigned int i, int *left)
{
  FETCH *eh = fetch_easy_init();
  fetch_easy_setopt(eh, FETCHOPT_WRITEFUNCTION, write_cb);
  fetch_easy_setopt(eh, FETCHOPT_URL, urls[i]);
  fetch_easy_setopt(eh, FETCHOPT_PRIVATE, urls[i]);
  fetch_multi_add_handle(cm, eh);
  (*left)++;
}

int main(void)
{
  FETCHM *cm;
  FETCHMsg *msg;
  unsigned int transfers = 0;
  int msgs_left = -1;
  int left = 0;

  fetch_global_init(FETCH_GLOBAL_ALL);
  cm = fetch_multi_init();

  /* Limit the amount of simultaneous connections fetch should allow: */
  fetch_multi_setopt(cm, FETCHMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

  for (transfers = 0; transfers < MAX_PARALLEL && transfers < NUM_URLS;
       transfers++)
    add_transfer(cm, transfers, &left);

  do
  {
    int still_alive = 1;
    fetch_multi_perform(cm, &still_alive);

    /* !checksrc! disable EQUALSNULL 1 */
    while ((msg = fetch_multi_info_read(cm, &msgs_left)) != NULL)
    {
      if (msg->msg == FETCHMSG_DONE)
      {
        char *url;
        FETCH *e = msg->easy_handle;
        fetch_easy_getinfo(msg->easy_handle, FETCHINFO_PRIVATE, &url);
        fprintf(stderr, "R: %d - %s <%s>\n",
                msg->data.result, fetch_easy_strerror(msg->data.result), url);
        fetch_multi_remove_handle(cm, e);
        fetch_easy_cleanup(e);
        left--;
      }
      else
      {
        fprintf(stderr, "E: FETCHMsg (%d)\n", msg->msg);
      }
      if (transfers < NUM_URLS)
        add_transfer(cm, transfers++, &left);
    }
    if (left)
      fetch_multi_wait(cm, NULL, 0, 1000, NULL);

  } while (left);

  fetch_multi_cleanup(cm);
  fetch_global_cleanup();

  return EXIT_SUCCESS;
}
