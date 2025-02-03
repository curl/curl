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
 * IMAP with implicit SSL
 * </DESC>
 */

#include <stdio.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to fetch mail using libfetch's IMAP
 * capabilities. It builds on the imap-fetch.c example adding transport
 * security to protect the authentication details from being snooped.
 *
 * Note that this example requires libfetch 7.30.0 or above.
 */

int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  fetch = fetch_easy_init();
  if(fetch) {
    /* Set username and password */
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "user");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "secret");

    /* This fetches message 1 from the user's inbox. Note the use of
    * imaps:// rather than imap:// to request a SSL based connection. */
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "imaps://imap.example.com/INBOX/;UID=1");

    /* If you want to connect to a site who is not using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the FETCHOPT_CAPATH option might come handy for
     * you. */
#ifdef SKIP_PEER_VERIFICATION
    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
#endif

    /* If the site you are connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libfetch refuses to connect. You can skip this
     * check, but it makes the connection insecure. */
#ifdef SKIP_HOSTNAME_VERIFICATION
    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);
#endif

    /* Since the traffic is encrypted, it is useful to turn on debug
     * information within libfetch to see what is happening during the
     * transfer */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* Perform the fetch */
    res = fetch_easy_perform(fetch);

    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* Always cleanup */
    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
