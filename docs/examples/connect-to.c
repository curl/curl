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
 * Use FETCHOPT_CONNECT_TO to connect to "wrong" hostname
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

int main(void)
{
   FETCH *fetch;
   FETCHcode res = FETCHE_OK;

   /*
     Each single string should be written using the format
     HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT where HOST is the host of the
     request, PORT is the port of the request, CONNECT-TO-HOST is the host name
     to connect to, and CONNECT-TO-PORT is the port to connect to.
    */
   /* instead of fetch.se:443, it resolves and uses example.com:443 but in other
      aspects work as if it still is fetch.se */
   struct fetch_slist *host = fetch_slist_append(NULL,
                                                 "fetch.se:443:example.com:443");

   fetch = fetch_easy_init();
   if (fetch)
   {
      fetch_easy_setopt(fetch, FETCHOPT_CONNECT_TO, host);
      fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
      fetch_easy_setopt(fetch, FETCHOPT_URL, "https://fetch.se/");

      /* since this connects to the wrong host, checking the host name in the
         server certificate fails, so unless we disable the check libfetch
         returns FETCHE_PEER_FAILED_VERIFICATION */
      fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);

      /* Letting the wrong host name in the certificate be okay, the transfer
         goes through but (most likely) causes a 404 or similar because it sends
         an unknown name in the Host: header field */
      res = fetch_easy_perform(fetch);

      /* always cleanup */
      fetch_easy_cleanup(fetch);
   }

   fetch_slist_free_all(host);

   return (int)res;
}
