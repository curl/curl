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

#define EXCESSIVE 10 * 1000 * 1000
FETCHcode test(char *URL)
{
       FETCHcode res = FETCHE_OK;
       FETCH *fetch = NULL;
       char *longurl = malloc(EXCESSIVE);
       FETCHU *u;
       (void)URL;

       if (!longurl)
              return (FETCHcode)1;

       memset(longurl, 'a', EXCESSIVE);
       longurl[EXCESSIVE - 1] = 0;

       global_init(FETCH_GLOBAL_ALL);
       easy_init(fetch);

       res = fetch_easy_setopt(fetch, FETCHOPT_URL, longurl);
       printf("FETCHOPT_URL %d bytes URL == %d\n",
              EXCESSIVE, res);

       res = fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, longurl);
       printf("FETCHOPT_POSTFIELDS %d bytes data == %d\n",
              EXCESSIVE, res);

       u = fetch_url();
       if (u)
       {
              FETCHUcode uc = fetch_url_set(u, FETCHUPART_URL, longurl, 0);
              printf("FETCHUPART_URL %d bytes URL == %d (%s)\n",
                     EXCESSIVE, (int)uc, fetch_url_strerror(uc));
              uc = fetch_url_set(u, FETCHUPART_SCHEME, longurl, FETCHU_NON_SUPPORT_SCHEME);
              printf("FETCHUPART_SCHEME %d bytes scheme == %d (%s)\n",
                     EXCESSIVE, (int)uc, fetch_url_strerror(uc));
              uc = fetch_url_set(u, FETCHUPART_USER, longurl, 0);
              printf("FETCHUPART_USER %d bytes user == %d (%s)\n",
                     EXCESSIVE, (int)uc, fetch_url_strerror(uc));
              fetch_url_cleanup(u);
       }

test_cleanup:
       free(longurl);
       fetch_easy_cleanup(fetch);
       fetch_global_cleanup();

       return res; /* return the final return code */
}
